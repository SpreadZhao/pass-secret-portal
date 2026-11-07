#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/random.h>
#include <unistd.h>

#include <systemd/sd-bus.h>
#include <systemd/sd-event.h>

#define PORTAL_NAME "org.freedesktop.impl.portal.desktop.passsecret"
#define FRONTEND_NAME "org.freedesktop.portal.Desktop"
#define PORTAL_PATH "/org/freedesktop/portal/desktop"
#define REQUEST_PREFIX PORTAL_PATH "/request/"
#define STORE_NAME "org.freedesktop.secrets"
#define STORE_PATH "/org/freedesktop/secrets"
#define SERVICE_IFACE "org.freedesktop.Secret.Service"
#define COLLECTION_IFACE "org.freedesktop.Secret.Collection"
#define ITEM_IFACE "org.freedesktop.Secret.Item"
#define SCHEMA "org.freedesktop.portal.Secret"
#define FORMAT_ATTRIBUTE "pass-secret-portal-format"
#define FORMAT "hex-v1"
#define KEY_SIZE 64
#define HEX_SIZE (KEY_SIZE * 2)
#define MAX_REQUESTS 64
#define TIMEOUT_USEC (UINT64_C(120) * 1000000)

typedef struct App App;
typedef struct Request Request;

enum Stage { OPEN_SESSION, READ_ALIAS, SEARCH, ATTRIBUTES, GET_SECRET, CREATE_ITEM };

struct Request {
    App *app;
    Request *next;
    sd_bus_message *response;
    sd_bus_slot *object, *rpc;
    sd_event_source *deadline, *writable;
    char *path, *app_id, *store_owner, *session, *collection, *item;
    unsigned char key[KEY_SIZE];
    char hex[HEX_SIZE + 1];
    size_t written;
    int fd;
    enum Stage stage;
    bool cancelled, replied;
};

struct App {
    sd_bus *bus;
    sd_event *event;
    sd_bus_slot *object, *owner_watch;
    sd_event_source *sigterm, *sigint;
    char *frontend_owner;
    Request *head, *tail, *active;
    unsigned count;
    bool stopping;
};

static void start_next(App *app);
static void finish(Request *request, unsigned response);
static int store_reply(sd_bus_message *message, void *userdata, sd_bus_error *error);

static void report(const char *reason)
{
    fprintf(stderr, "pass-secret-portal: %s\n", reason);
}

static bool authorized(App *app, sd_bus_message *message)
{
    const char *sender = sd_bus_message_get_sender(message);
    return sender && app->frontend_owner && !strcmp(sender, app->frontend_owner);
}

static void reply(Request *request, unsigned response)
{
    if (!request->replied) {
        if (sd_bus_message_append(request->response, "ua{sv}", response, 0) >= 0)
            (void)sd_bus_send(request->app->bus, request->response, NULL);
        request->replied = true;
    }
    request->object = sd_bus_slot_unref(request->object);
    request->deadline = sd_event_source_unref(request->deadline);
}

static void close_session(Request *request)
{
    sd_bus_message *message = NULL;
    if (request->session && request->store_owner &&
        sd_bus_message_new_method_call(request->app->bus, &message,
            request->store_owner, request->session,
            "org.freedesktop.Secret.Session", "Close") >= 0) {
        (void)sd_bus_message_set_expect_reply(message, 0);
        (void)sd_bus_send(request->app->bus, message, NULL);
    }
    sd_bus_message_unref(message);
}

static void destroy(Request *request)
{
    request->object = sd_bus_slot_unref(request->object);
    request->rpc = sd_bus_slot_unref(request->rpc);
    request->deadline = sd_event_source_unref(request->deadline);
    request->writable = sd_event_source_unref(request->writable);
    close_session(request);
    if (request->fd >= 0)
        close(request->fd);
    sd_bus_message_unref(request->response);
    free(request->path);
    free(request->app_id);
    free(request->store_owner);
    free(request->session);
    free(request->collection);
    free(request->item);
    explicit_bzero(request->key, sizeof(request->key));
    explicit_bzero(request->hex, sizeof(request->hex));
    free(request);
}

static void finish(Request *request, unsigned response)
{
    App *app = request->app;
    Request *previous = NULL;
    for (Request *entry = app->head; entry && entry != request; entry = entry->next)
        previous = entry;
    reply(request, response);
    if (previous)
        previous->next = request->next;
    else
        app->head = request->next;
    if (app->tail == request)
        app->tail = previous;
    if (app->active == request)
        app->active = NULL;
    app->count--;
    destroy(request);
    start_next(app);
}

static void fail(Request *request, const char *reason)
{
    report(reason);
    finish(request, 2);
}

static void cancel(Request *request, unsigned response)
{
    request->cancelled = true;
    request->writable = sd_event_source_unref(request->writable);
    if (request->fd >= 0) {
        close(request->fd);
        request->fd = -1;
    }
    reply(request, response);
    /* Wait for the store operation to finish before starting the next transaction. */
    if (!request->rpc)
        finish(request, response);
}

static int request_close(sd_bus_message *message, void *userdata, sd_bus_error *error)
{
    Request *request = userdata;
    (void)error;
    if (!authorized(request->app, message))
        return sd_bus_reply_method_errorf(message, SD_BUS_ERROR_ACCESS_DENIED,
                                         "Only the portal frontend may close requests");
    cancel(request, 1);
    return sd_bus_reply_method_return(message, NULL);
}

static const sd_bus_vtable request_vtable[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_METHOD("Close", "", "", request_close, SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_VTABLE_END
};

static int timed_out(sd_event_source *source, uint64_t usec, void *userdata)
{
    (void)source;
    (void)usec;
    cancel(userdata, 2);
    return 0;
}

static int new_call(Request *request, sd_bus_message **message, const char *path,
                    const char *interface, const char *member)
{
    return sd_bus_message_new_method_call(request->app->bus, message,
        request->store_owner ? request->store_owner : STORE_NAME,
        path, interface, member);
}

static void send_call(Request *request, sd_bus_message *message, enum Stage stage)
{
    request->stage = stage;
    int result = sd_bus_call_async(request->app->bus, &request->rpc, message,
                                  store_reply, request, TIMEOUT_USEC);
    sd_bus_message_unref(message);
    if (result < 0)
        fail(request, "could not send Secret Service request");
}

static void simple_call(Request *request, enum Stage stage, const char *path,
                        const char *interface, const char *member,
                        const char *signature, ...)
{
    sd_bus_message *message = NULL;
    int result = new_call(request, &message, path, interface, member);
    if (result >= 0 && signature) {
        va_list args;
        va_start(args, signature);
        result = sd_bus_message_appendv(message, signature, args);
        va_end(args);
    }
    if (result < 0) {
        sd_bus_message_unref(message);
        fail(request, "could not construct Secret Service request");
        return;
    }
    send_call(request, message, stage);
}

static int string_entry(sd_bus_message *message, const char *key, const char *value)
{
    int result = sd_bus_message_open_container(message, 'e', "ss");
    if (result >= 0)
        result = sd_bus_message_append(message, "ss", key, value);
    if (result >= 0)
        result = sd_bus_message_close_container(message);
    return result;
}

static int attributes(sd_bus_message *message, const char *app_id, bool with_format)
{
    int result = sd_bus_message_open_container(message, 'a', "{ss}");
    if (result >= 0)
        result = string_entry(message, "xdg:schema", SCHEMA);
    if (result >= 0)
        result = string_entry(message, "app_id", app_id);
    if (result >= 0 && with_format)
        result = string_entry(message, FORMAT_ATTRIBUTE, FORMAT);
    if (result >= 0)
        result = sd_bus_message_close_container(message);
    return result;
}

static void search(Request *request)
{
    sd_bus_message *message = NULL;
    int result = new_call(request, &message, request->collection,
                          COLLECTION_IFACE, "SearchItems");
    /* Check format after lookup to avoid generating a new key for a damaged record. */
    if (result >= 0)
        result = attributes(message, request->app_id, false);
    if (result < 0) {
        sd_bus_message_unref(message);
        fail(request, "could not construct key lookup");
        return;
    }
    send_call(request, message, SEARCH);
}

static int label_property(sd_bus_message *message, const char *label)
{
    int result = sd_bus_message_open_container(message, 'e', "sv");
    if (result >= 0)
        result = sd_bus_message_append(message, "s", ITEM_IFACE ".Label");
    if (result >= 0)
        result = sd_bus_message_open_container(message, 'v', "s");
    if (result >= 0)
        result = sd_bus_message_append(message, "s", label);
    if (result >= 0)
        result = sd_bus_message_close_container(message);
    if (result >= 0)
        result = sd_bus_message_close_container(message);
    return result;
}

static int attributes_property(sd_bus_message *message, const char *app_id)
{
    int result = sd_bus_message_open_container(message, 'e', "sv");
    if (result >= 0)
        result = sd_bus_message_append(message, "s", ITEM_IFACE ".Attributes");
    if (result >= 0)
        result = sd_bus_message_open_container(message, 'v', "a{ss}");
    if (result >= 0)
        result = attributes(message, app_id, true);
    if (result >= 0)
        result = sd_bus_message_close_container(message);
    if (result >= 0)
        result = sd_bus_message_close_container(message);
    return result;
}

static int random_key(Request *request)
{
    size_t offset = 0;
    while (offset < KEY_SIZE) {
        ssize_t count = getrandom(request->key + offset, KEY_SIZE - offset, 0);
        if (count < 0) {
            if (errno == EINTR)
                continue;
            return -errno;
        }
        if (!count)
            return -EIO;
        offset += (size_t)count;
    }
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < KEY_SIZE; i++) {
        request->hex[2 * i] = digits[request->key[i] >> 4];
        request->hex[2 * i + 1] = digits[request->key[i] & 15];
    }
    return 0;
}

static void create_item(Request *request)
{
    sd_bus_message *message = NULL;
    char *label = NULL;
    int result = random_key(request);
    if (result >= 0 && asprintf(&label, "Secret Portal key for %s", request->app_id) < 0)
        result = -ENOMEM;
    if (result >= 0)
        result = new_call(request, &message, request->collection,
                          COLLECTION_IFACE, "CreateItem");
    if (result >= 0)
        result = sd_bus_message_open_container(message, 'a', "{sv}");
    if (result >= 0)
        result = label_property(message, label);
    if (result >= 0)
        result = attributes_property(message, request->app_id);
    if (result >= 0)
        result = sd_bus_message_close_container(message);
    if (result >= 0)
        result = sd_bus_message_open_container(message, 'r', "oayays");
    if (result >= 0)
        result = sd_bus_message_append(message, "o", request->session);
    if (result >= 0)
        result = sd_bus_message_append_array(message, 'y', NULL, 0);
    if (result >= 0)
        result = sd_bus_message_append_array(message, 'y', request->hex, HEX_SIZE);
    if (result >= 0)
        result = sd_bus_message_append(message, "s", "text/plain");
    if (result >= 0)
        result = sd_bus_message_close_container(message);
    if (result >= 0)
        result = sd_bus_message_append(message, "b", 0);
    free(label);
    if (result < 0) {
        sd_bus_message_unref(message);
        fail(request, "could not construct key creation");
        return;
    }
    send_call(request, message, CREATE_ITEM);
}

static int hex_digit(unsigned char value)
{
    if (value >= '0' && value <= '9')
        return value - '0';
    if (value >= 'a' && value <= 'f')
        return value - 'a' + 10;
    return -1;
}

static int read_secret(Request *request, sd_bus_message *message)
{
    const char *session, *content_type;
    const void *parameters, *value;
    size_t parameters_size, size;
    int result = sd_bus_message_enter_container(message, 'r', "oayays");
    if (result <= 0)
        return -EINVAL;
    if (sd_bus_message_read(message, "o", &session) <= 0 ||
        strcmp(session, request->session) ||
        sd_bus_message_read_array(message, 'y', &parameters, &parameters_size) < 0 ||
        parameters_size != 0 ||
        sd_bus_message_read_array(message, 'y', &value, &size) < 0 ||
        size != HEX_SIZE ||
        sd_bus_message_read(message, "s", &content_type) <= 0 ||
        strcmp(content_type, "text/plain"))
        return -EINVAL;
    const unsigned char *hex = value;
    for (size_t i = 0; i < KEY_SIZE; i++) {
        int high = hex_digit(hex[2 * i]), low = hex_digit(hex[2 * i + 1]);
        if (high < 0 || low < 0)
            return -EINVAL;
        request->key[i] = (unsigned char)((high << 4) | low);
    }
    return sd_bus_message_exit_container(message);
}

static int valid_attributes(Request *request, sd_bus_message *message)
{
    bool schema = false, app_id = false, format = false;
    if (sd_bus_message_enter_container(message, 'v', "a{ss}") <= 0 ||
        sd_bus_message_enter_container(message, 'a', "{ss}") <= 0)
        return -EINVAL;
    int result;
    while ((result = sd_bus_message_enter_container(message, 'e', "ss")) > 0) {
        const char *key, *value;
        if (sd_bus_message_read(message, "ss", &key, &value) <= 0)
            return -EINVAL;
        if (!strcmp(key, "xdg:schema")) {
            if (schema || strcmp(value, SCHEMA))
                return -EINVAL;
            schema = true;
        } else if (!strcmp(key, "app_id")) {
            if (app_id || strcmp(value, request->app_id))
                return -EINVAL;
            app_id = true;
        } else if (!strcmp(key, FORMAT_ATTRIBUTE)) {
            if (format || strcmp(value, FORMAT))
                return -EINVAL;
            format = true;
        }
        if (sd_bus_message_exit_container(message) < 0)
            return -EINVAL;
    }
    return result < 0 || !schema || !app_id || !format ? -EINVAL : 0;
}

static void write_key(Request *request);

static int write_ready(sd_event_source *source, int fd, uint32_t events, void *userdata)
{
    (void)source;
    (void)fd;
    (void)events;
    write_key(userdata);
    return 0;
}

static void write_key(Request *request)
{
    while (request->written < KEY_SIZE) {
        ssize_t count = write(request->fd, request->key + request->written,
                              KEY_SIZE - request->written);
        if (count > 0) {
            request->written += (size_t)count;
            continue;
        }
        if (count < 0 && errno == EINTR)
            continue;
        if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (!request->writable && sd_event_add_io(request->app->event,
                    &request->writable, request->fd, EPOLLOUT, write_ready, request) < 0)
                fail(request, "could not wait for writable secret descriptor");
            return;
        }
        fail(request, "could not write secret descriptor");
        return;
    }
    finish(request, 0);
}

static void deliver(Request *request)
{
    int flags = fcntl(request->fd, F_GETFL);
    if (flags < 0 || fcntl(request->fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        fail(request, "could not prepare secret descriptor");
        return;
    }
    write_key(request);
}

static int store_reply(sd_bus_message *message, void *userdata, sd_bus_error *error)
{
    Request *request = userdata;
    (void)error;
    request->rpc = sd_bus_slot_unref(request->rpc);
    if (sd_bus_message_is_method_error(message, NULL)) {
        fail(request, "Secret Service operation failed");
        return 1;
    }
    /* Read the session path even after cancellation so cleanup can close it. */
    if (request->stage == OPEN_SESSION) {
        const char *session;
        if (sd_bus_message_skip(message, "v") <= 0 ||
            sd_bus_message_read(message, "o", &session) <= 0 || !strcmp(session, "/")) {
            fail(request, "invalid Secret Service session");
            return 1;
        }
        request->session = strdup(session);
        request->store_owner = strdup(sd_bus_message_get_sender(message));
        if (!request->session || !request->store_owner) {
            fail(request, "out of memory");
            return 1;
        }
    }
    if (request->cancelled) {
        finish(request, 1);
        return 1;
    }
    const char *path, *extra;
    int result;
    switch (request->stage) {
    case OPEN_SESSION:
        simple_call(request, READ_ALIAS, STORE_PATH, SERVICE_IFACE,
                    "ReadAlias", "s", "default");
        break;
    case READ_ALIAS:
        if (sd_bus_message_read(message, "o", &path) <= 0 || !strcmp(path, "/")) {
            fail(request, "default Secret Service collection is unavailable");
            break;
        }
        request->collection = strdup(path);
        if (!request->collection)
            fail(request, "out of memory");
        else
            search(request);
        break;
    case SEARCH:
        if (sd_bus_message_enter_container(message, 'a', "o") <= 0) {
            fail(request, "invalid key lookup response");
            break;
        }
        result = sd_bus_message_read(message, "o", &path);
        if (result < 0) {
            fail(request, "invalid key lookup response");
        } else if (!result) {
            create_item(request);
        } else {
            request->item = strdup(path);
            if (!request->item) {
                fail(request, "out of memory");
                break;
            }
            if (sd_bus_message_read(message, "o", &extra) != 0) {
                fail(request, "multiple keys found for application");
                break;
            }
            simple_call(request, ATTRIBUTES, request->item,
                        "org.freedesktop.DBus.Properties", "Get", "ss",
                        ITEM_IFACE, "Attributes");
        }
        break;
    case ATTRIBUTES:
        if (valid_attributes(request, message) < 0)
            fail(request, "stored key attributes are incompatible");
        else
            simple_call(request, GET_SECRET, request->item, ITEM_IFACE,
                        "GetSecret", "o", request->session);
        break;
    case GET_SECRET:
        if (read_secret(request, message) < 0)
            fail(request, "stored key is not a valid hex-v1 secret");
        else
            deliver(request);
        break;
    case CREATE_ITEM:
        if (sd_bus_message_read(message, "oo", &path, &extra) <= 0 ||
            !strcmp(path, "/") || strcmp(extra, "/"))
            fail(request, "key creation failed or requires an unsupported prompt");
        else
            deliver(request);
        break;
    }
    return 1;
}

static void start_next(App *app)
{
    if (app->stopping || app->active || !app->head)
        return;
    app->active = app->head;
    simple_call(app->active, OPEN_SESSION, STORE_PATH, SERVICE_IFACE,
                "OpenSession", "sv", "plain", "s", "");
}

static int retrieve_secret(sd_bus_message *message, void *userdata, sd_bus_error *error)
{
    App *app = userdata;
    const char *path, *app_id;
    int fd;
    (void)error;
    if (!authorized(app, message))
        return sd_bus_reply_method_errorf(message, SD_BUS_ERROR_ACCESS_DENIED,
                                         "Only the portal frontend may retrieve secrets");
    if (sd_bus_message_read(message, "osh", &path, &app_id, &fd) <= 0 ||
        sd_bus_message_skip(message, "a{sv}") <= 0 ||
        strncmp(path, REQUEST_PREFIX, strlen(REQUEST_PREFIX)) || strlen(app_id) > 1024)
        return sd_bus_reply_method_errorf(message, SD_BUS_ERROR_INVALID_ARGS,
                                         "Invalid secret request");
    for (Request *entry = app->head; entry; entry = entry->next)
        if (!strcmp(entry->path, path))
            return sd_bus_reply_method_errorf(message, SD_BUS_ERROR_INVALID_ARGS,
                                             "Request path is already in use");
    if (app->count >= MAX_REQUESTS)
        return sd_bus_reply_method_return(message, "ua{sv}", 2u, 0);
    Request *request = calloc(1, sizeof(*request));
    if (!request)
        return -ENOMEM;
    request->app = app;
    request->fd = fcntl(fd, F_DUPFD_CLOEXEC, 3);
    request->path = strdup(path);
    request->app_id = strdup(app_id);
    int result = request->fd < 0 ? -errno : 0;
    if (!request->path || !request->app_id)
        result = -ENOMEM;
    if (result >= 0)
        result = sd_bus_message_new_method_return(message, &request->response);
    if (result >= 0)
        result = sd_bus_add_object_vtable(app->bus, &request->object, path,
            "org.freedesktop.impl.portal.Request", request_vtable, request);
    if (result >= 0)
        result = sd_event_add_time_relative(app->event, &request->deadline,
            CLOCK_MONOTONIC, TIMEOUT_USEC, 100000, timed_out, request);
    if (result < 0) {
        destroy(request);
        return sd_bus_reply_method_return(message, "ua{sv}", 2u, 0);
    }
    if (app->tail)
        app->tail->next = request;
    else
        app->head = request;
    app->tail = request;
    app->count++;
    start_next(app);
    return 1;
}

static int version(sd_bus *bus, const char *path, const char *interface,
                   const char *property, sd_bus_message *reply_message,
                   void *userdata, sd_bus_error *error)
{
    (void)bus;
    (void)path;
    (void)interface;
    (void)property;
    (void)userdata;
    (void)error;
    return sd_bus_message_append(reply_message, "u", 1u);
}

static const sd_bus_vtable portal_vtable[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_METHOD("RetrieveSecret", "osha{sv}", "ua{sv}", retrieve_secret,
                  SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_PROPERTY("version", "u", version, 0, SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_VTABLE_END
};

static int owner_changed(sd_bus_message *message, void *userdata, sd_bus_error *error)
{
    App *app = userdata;
    const char *name, *old_owner, *new_owner;
    (void)error;
    if (sd_bus_message_read(message, "sss", &name, &old_owner, &new_owner) <= 0 ||
        strcmp(name, FRONTEND_NAME))
        return 0;
    free(app->frontend_owner);
    app->frontend_owner = *new_owner ? strdup(new_owner) : NULL;
    if (*new_owner && !app->frontend_owner)
        return -ENOMEM;
    if (*old_owner) {
        /* Do not start queued requests from the disconnected frontend. */
        app->stopping = true;
        Request *request = app->head;
        while (request) {
            Request *next = request->next;
            cancel(request, 1);
            request = next;
        }
        app->stopping = false;
        start_next(app);
    }
    return 0;
}

static int terminate(sd_event_source *source, const struct signalfd_siginfo *info,
                     void *userdata)
{
    (void)source;
    (void)info;
    App *app = userdata;
    return sd_event_exit(app->event, 0);
}

int main(int argc, char **argv)
{
    if (argc == 2 && !strcmp(argv[1], "--version")) {
        puts("pass-secret-portal 0.1.0");
        return EXIT_SUCCESS;
    }
    if (argc == 2 && !strcmp(argv[1], "--help")) {
        puts("Usage: pass-secret-portal [--help|--version]\n"
             "Serve the Secret portal using the session's Secret Service.");
        return EXIT_SUCCESS;
    }
    if (argc != 1) {
        fputs("Usage: pass-secret-portal [--help|--version]\n", stderr);
        return EXIT_FAILURE;
    }
    (void)signal(SIGPIPE, SIG_IGN);
    sigset_t signals;
    sigemptyset(&signals);
    sigaddset(&signals, SIGINT);
    sigaddset(&signals, SIGTERM);
    if (sigprocmask(SIG_BLOCK, &signals, NULL) < 0)
        return EXIT_FAILURE;
    App app = {0};
    int result = sd_event_default(&app.event);
    if (result >= 0)
        result = sd_bus_open_user(&app.bus);
    if (result >= 0)
        result = sd_bus_attach_event(app.bus, app.event, 0);
    if (result >= 0)
        result = sd_bus_match_signal(app.bus, &app.owner_watch, "org.freedesktop.DBus",
            "/org/freedesktop/DBus", "org.freedesktop.DBus", "NameOwnerChanged",
            owner_changed, &app);
    if (result >= 0) {
        sd_bus_message *message = NULL;
        sd_bus_error error = SD_BUS_ERROR_NULL;
        int found = sd_bus_call_method(app.bus, "org.freedesktop.DBus",
            "/org/freedesktop/DBus", "org.freedesktop.DBus", "GetNameOwner",
            &error, &message, "s", FRONTEND_NAME);
        if (found >= 0) {
            const char *owner;
            if (sd_bus_message_read(message, "s", &owner) > 0)
                app.frontend_owner = strdup(owner);
            if (!app.frontend_owner)
                result = -ENOMEM;
        } else if (!sd_bus_error_has_name(&error, SD_BUS_ERROR_NAME_HAS_NO_OWNER)) {
            result = found;
        }
        sd_bus_error_free(&error);
        sd_bus_message_unref(message);
    }
    if (result >= 0)
        result = sd_bus_add_object_vtable(app.bus, &app.object, PORTAL_PATH,
            "org.freedesktop.impl.portal.Secret", portal_vtable, &app);
    if (result >= 0)
        result = sd_event_add_signal(app.event, &app.sigterm, SIGTERM, terminate, &app);
    if (result >= 0)
        result = sd_event_add_signal(app.event, &app.sigint, SIGINT, terminate, &app);
    if (result >= 0)
        result = sd_bus_request_name(app.bus, PORTAL_NAME, 0);
    if (result >= 0)
        result = sd_event_loop(app.event);
    if (result < 0)
        report(strerror(-result));
    app.stopping = true;
    while (app.head)
        finish(app.head, 2);
    sd_event_source_unref(app.sigterm);
    sd_event_source_unref(app.sigint);
    sd_bus_slot_unref(app.object);
    sd_bus_slot_unref(app.owner_watch);
    free(app.frontend_owner);
    sd_bus_flush_close_unref(app.bus);
    sd_event_unref(app.event);
    return result < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
