#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dbus/dbus.h>
#include <sys/time.h>
#include <time.h>

int main(int argc, char* argv[]) {
  DBusError error = DBUS_ERROR_INIT;
  DBusConnection* connection = dbus_bus_get(DBUS_BUS_SYSTEM, &error);
  DBusMessage* message =
      dbus_message_new_method_call(DBUS_SERVICE_DBUS,
                                   DBUS_PATH_DBUS,
                                   DBUS_INTERFACE_DBUS,
                                   "GetConnectionUnixProcessID");
  if (message == NULL)
    printf("OOM");

  const char* unique = ":1.0";
  if (!dbus_message_append_args(
          message, DBUS_TYPE_STRING, &unique, DBUS_TYPE_INVALID))
    printf("OOM");

  DBusMessage* reply = dbus_connection_send_with_reply_and_block(
      connection, message, -1, &error);

  unsigned int pid;
  if (dbus_message_get_args(
          reply, &error, DBUS_TYPE_UINT32, &pid, DBUS_TYPE_INVALID)) {
    printf("\nGetConnectionUnixProcessID returned %u\n", pid);
  }

  dbus_clear_message(&reply);
  dbus_clear_message(&message);
  exit(0);
}
