#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dbus/dbus.h>
#include <sys/time.h>
#include <time.h>

#define EAVESDROPPING_RULE "eavesdrop=true"

#ifndef STDOUT_FILENO
#define STDOUT_FILENO 1
#endif

/* http://www.tcpdump.org/linktypes.html */
#define LINKTYPE_DBUS 231

void dbus_get_real_time(long* tv_sec, long* tv_usec) {
  /* FILETIME ft; */
  dbus_uint64_t time64;

  /* GetSystemTimeAsFileTime(&ft); */

  /* memcpy(&time64, &ft, sizeof(time64)); */

  /* Convert from 100s of nanoseconds since 1601-01-01
   * to Unix epoch. Yes, this is Y2038 unsafe.
   */
  time64 -= DBUS_INT64_CONSTANT(116444736000000000);
  time64 /= 10;

  if (tv_sec)
    *tv_sec = time64 / 1000000;

  if (tv_usec)
    *tv_usec = time64 % 1000000;
}

#define TRAP_NULL_STRING(str) ((str) ? (str) : "<none>")

typedef enum {
  PROFILE_ATTRIBUTE_FLAG_SERIAL = 1,
  PROFILE_ATTRIBUTE_FLAG_REPLY_SERIAL = 2,
  PROFILE_ATTRIBUTE_FLAG_SENDER = 4,
  PROFILE_ATTRIBUTE_FLAG_DESTINATION = 8,
  PROFILE_ATTRIBUTE_FLAG_PATH = 16,
  PROFILE_ATTRIBUTE_FLAG_INTERFACE = 32,
  PROFILE_ATTRIBUTE_FLAG_MEMBER = 64,
  PROFILE_ATTRIBUTE_FLAG_ERROR_NAME = 128
} ProfileAttributeFlags;

static void profile_print_headers(void) {
  printf(
      "#type\ttimestamp\tserial\tsender\tdestination\tpath\tinterface\tmember"
      "\n");
  printf("#\t\t\t\t\tin_reply_to\n");
}

static void profile_print_with_attrs(const char* type,
                                     DBusMessage* message,
                                     long sec,
                                     long usec,
                                     ProfileAttributeFlags attrs) {
  printf("%s\t%ld.%06ld", type, sec, usec);

  if (attrs & PROFILE_ATTRIBUTE_FLAG_SERIAL)
    printf("\t%u", dbus_message_get_serial(message));

  if (attrs & PROFILE_ATTRIBUTE_FLAG_SENDER)
    printf("\t%s", TRAP_NULL_STRING(dbus_message_get_sender(message)));

  if (attrs & PROFILE_ATTRIBUTE_FLAG_DESTINATION)
    printf("\t%s", TRAP_NULL_STRING(dbus_message_get_destination(message)));

  if (attrs & PROFILE_ATTRIBUTE_FLAG_REPLY_SERIAL)
    printf("\t%u", dbus_message_get_reply_serial(message));

  if (attrs & PROFILE_ATTRIBUTE_FLAG_PATH)
    printf("\t%s", TRAP_NULL_STRING(dbus_message_get_path(message)));

  if (attrs & PROFILE_ATTRIBUTE_FLAG_INTERFACE)
    printf("\t%s", TRAP_NULL_STRING(dbus_message_get_interface(message)));

  if (attrs & PROFILE_ATTRIBUTE_FLAG_MEMBER)
    printf("\t%s", TRAP_NULL_STRING(dbus_message_get_member(message)));

  if (attrs & PROFILE_ATTRIBUTE_FLAG_ERROR_NAME)
    printf("\t%s", TRAP_NULL_STRING(dbus_message_get_error_name(message)));

  printf("\n");
}

static DBusHandlerResult profile_filter_func(DBusConnection* connection,
                                             DBusMessage* message,
                                             void* user_data) {
  static dbus_bool_t first = TRUE;
  long sec = 0, usec = 0;

  if (first) {
    profile_print_headers();
    first = FALSE;
  }

  dbus_get_real_time(&sec, &usec);

  switch (dbus_message_get_type(message)) {
  case DBUS_MESSAGE_TYPE_METHOD_CALL:
    profile_print_with_attrs(
        "mc",
        message,
        sec,
        usec,
        PROFILE_ATTRIBUTE_FLAG_SERIAL | PROFILE_ATTRIBUTE_FLAG_SENDER |
            PROFILE_ATTRIBUTE_FLAG_DESTINATION | PROFILE_ATTRIBUTE_FLAG_PATH |
            PROFILE_ATTRIBUTE_FLAG_INTERFACE | PROFILE_ATTRIBUTE_FLAG_MEMBER);
    break;
  case DBUS_MESSAGE_TYPE_METHOD_RETURN:
    profile_print_with_attrs("mr",
                             message,
                             sec,
                             usec,
                             PROFILE_ATTRIBUTE_FLAG_SERIAL |
                                 PROFILE_ATTRIBUTE_FLAG_SENDER |
                                 PROFILE_ATTRIBUTE_FLAG_DESTINATION |
                                 PROFILE_ATTRIBUTE_FLAG_REPLY_SERIAL);
    break;
  case DBUS_MESSAGE_TYPE_ERROR:
    profile_print_with_attrs("err",
                             message,
                             sec,
                             usec,
                             PROFILE_ATTRIBUTE_FLAG_SERIAL |
                                 PROFILE_ATTRIBUTE_FLAG_SENDER |
                                 PROFILE_ATTRIBUTE_FLAG_DESTINATION |
                                 PROFILE_ATTRIBUTE_FLAG_REPLY_SERIAL);
    break;
  case DBUS_MESSAGE_TYPE_SIGNAL:
    profile_print_with_attrs(
        "sig",
        message,
        sec,
        usec,
        PROFILE_ATTRIBUTE_FLAG_SERIAL | PROFILE_ATTRIBUTE_FLAG_SENDER |
            PROFILE_ATTRIBUTE_FLAG_DESTINATION | PROFILE_ATTRIBUTE_FLAG_PATH |
            PROFILE_ATTRIBUTE_FLAG_INTERFACE | PROFILE_ATTRIBUTE_FLAG_MEMBER);
    break;
  default:
    printf("%s\t%ld.%06ld", "tun", sec, usec);
    break;
  }

  // todo add
  // Checks whether the message is a signal with the given interface and member
  // fields.
  if (dbus_message_is_signal(message, DBUS_INTERFACE_LOCAL, "Disconnected"))
    exit(0);

  return DBUS_HANDLER_RESULT_HANDLED;
}

typedef enum { BINARY_MODE_NOT, BINARY_MODE_RAW, BINARY_MODE_PCAP } BinaryMode;

static void only_one_type(dbus_bool_t* seen_bus_type, char* name) {
  if (*seen_bus_type) {
    fprintf(stderr, "I only support monitoring one bus at a time!\n");
  } else {
    *seen_bus_type = TRUE;
  }
}

int main(int argc, char* argv[]) {
  DBusConnection* connection;
  DBusError error;
  DBusBusType type = DBUS_BUS_SYSTEM;
  DBusHandleMessageFunction filter_func;
  char* address = NULL;
  dbus_bool_t seen_bus_type = FALSE;
  BinaryMode binary_mode = BINARY_MODE_NOT;
  int i = 0, j = 0, numFilters = 0;
  char** filters = NULL;

  /* Set stdout to be unbuffered; this is basically so that if people
   * do dbus-monitor > file, then send SIGINT via Control-C, they
   * don't lose the last chunk of messages.
   */
  setvbuf(stdout, NULL, _IOLBF, 0);

  for (i = 1; i < argc; i++) {
    char* arg = argv[i];

    if (!strcmp(arg, "--system")) {
      only_one_type(&seen_bus_type, argv[0]);
      type = DBUS_BUS_SYSTEM;
    } else if (!strcmp(arg, "--session")) {
      only_one_type(&seen_bus_type, argv[0]);
      type = DBUS_BUS_SESSION;
    } else if (!strcmp(arg, "--profile")) {
      filter_func = profile_filter_func;
      binary_mode = BINARY_MODE_NOT;
    } else {
      unsigned int filter_len;
      numFilters++;
      /* Prepend a rule (and a comma) to enable the monitor to eavesdrop.
       * Prepending allows the user to add eavesdrop=false at command line
       * in order to disable eavesdropping when needed */
      filter_len = strlen(EAVESDROPPING_RULE) + 1 + strlen(arg) + 1;

      filters = (char**)realloc(filters, numFilters * sizeof(char*));
      if (filters == NULL)
        exit(0);
      filters[j] = (char*)malloc(filter_len);
      if (filters[j] == NULL)
        exit(0);
      snprintf(filters[j], filter_len, "%s,%s", EAVESDROPPING_RULE, arg);
      j++;
    }
  }

  dbus_error_init(&error);
  connection = dbus_bus_get_private(type, &error);

  /* Receive o.fd.Peer messages as normal messages, rather than having
   * libdbus handle them internally, which is the wrong thing for
   * a monitor */
  /* dbus_connection_set_builtin_filters_enabled (connection, FALSE); */

  // todo
  // Adds a message filter.
  // Filters are handlers that are run on all incoming messages,
  //   prior to the objects regist
  if (!dbus_connection_add_filter(connection, filter_func, NULL, NULL)) {
    fprintf(stderr, "Couldn't add filter!\n");
    exit(1);
  }

  {
    DBusError error = DBUS_ERROR_INIT;
    DBusMessage* m;
    DBusMessage* r;
    int i;
    dbus_uint32_t zero = 0;
    DBusMessageIter appender, array_appender;

    // todo call the monitor interface.
    m = dbus_message_new_method_call(DBUS_SERVICE_DBUS,
                                     DBUS_PATH_DBUS,
                                     DBUS_INTERFACE_MONITORING,
                                     "BecomeMonitor");

    if (m == NULL)
      exit(0);

    dbus_message_iter_init_append(m, &appender);

    // todo
    /*
      Appends a container-typed value to the message.
      On success, you are required to append the contents of the container using
      the returned sub-iterator, and then call
      dbus_message_iter_close_container(). Container types are for example
      struct, variant, and array. For variants, the contained_signature should
      be the type of the single value inside the variant. For structs and dict
      entries, contained_signature should be NULL; it will be set to whatever
      types you write into the struct. For arrays, contained_signature should be
      the type of the array elements.

      If this function fails, the sub-iterator remains invalid, and must not be
      closed with dbus_message_iter_close_container() or abandoned with
      dbus_message_iter_abandon_container(). However, after this function has
      either succeeded or failed, it is valid to call
      dbus_message_iter_abandon_container_if_open().
     */
    if (!dbus_message_iter_open_container(
            &appender, DBUS_TYPE_ARRAY, "s", &array_appender))
      exit(0);

    for (i = 0; i < numFilters; i++) {
      if (!dbus_message_iter_append_basic(
              &array_appender, DBUS_TYPE_STRING, &filters[i]))
        exit(0);
    }

    // todo
    if (!dbus_message_iter_close_container(&appender, &array_appender) ||
        !dbus_message_iter_append_basic(&appender, DBUS_TYPE_UINT32, &zero))
      exit(0);

    r = dbus_connection_send_with_reply_and_block(connection, m, -1, &error);
    if (!r) {
      fprintf(stderr, "error %s: \"%s \n", error.name, error.message);
      return 0;
    }

    dbus_message_unref(r);
    dbus_message_unref(m);
  }

  {
    printf("\nMax fds %lu size %lu\n",
           dbus_connection_get_max_message_unix_fds(connection),
           dbus_connection_get_max_message_size(connection));
    DBusConnection* connection1 = dbus_bus_get(type, &error);
    if (connection == connection1) {
      printf("uday same\n");
    } else {
      printf("uday diff\n");
    }
    DBusMessage* message =
        dbus_message_new_method_call(DBUS_SERVICE_DBUS,
                                     DBUS_PATH_DBUS,
                                     DBUS_INTERFACE_DBUS,
                                     "GetConnectionUnixProcessID");
    if (message == NULL) {
      printf("OOM");
      return 0;
    }

    const char* unique = ":1.0";
    if (!dbus_message_append_args(
            message, DBUS_TYPE_STRING, &unique, DBUS_TYPE_INVALID)) {
      printf("OOM");
      return 0;
    }

    DBusMessage* reply = dbus_connection_send_with_reply_and_block(
        connection1, message, -1, &error);
    if (!reply) {
      fprintf(stderr, "error %s: \"%s \n", error.name, error.message);
      return 0;
    }

    unsigned int pid;
    if (dbus_message_get_args(
            reply, &error, DBUS_TYPE_UINT32, &pid, DBUS_TYPE_INVALID)) {
      printf("\nGetConnectionUnixProcessID returned %u\n", pid);
    }

    dbus_clear_message(&reply);
    dbus_clear_message(&message);
  }

  // todo
  while (dbus_connection_read_write_dispatch(connection, -1))
    ;
  dbus_connection_close(connection);
  dbus_connection_unref(connection);
  exit(0);
lose:
  fprintf(stderr, "Error: %s\n", error.message);
  exit(1);
}
