all:
	gcc -g -o monitor ./monitor.c \
		-I/usr/local/osquery/Cellar/dbus/1.12.20_2/include/dbus-1.0/ \
		-I/usr/local/osquery/Cellar/dbus/1.12.20_2/lib/dbus-1.0/include/ \
		-L /usr/local/osquery/Cellar/dbus/1.12.20_2/lib/ -ldbus-1 -lpthread \
		-DDBUS_INSIDE_DBUS_H -DDBUS_DISABLE_ASSERT
	gcc -g -o pid ./pid.c \
		-I/usr/local/osquery/Cellar/dbus/1.12.20_2/include/dbus-1.0/ \
		-I/usr/local/osquery/Cellar/dbus/1.12.20_2/lib/dbus-1.0/include/ \
		-L /usr/local/osquery/Cellar/dbus/1.12.20_2/lib/ -ldbus-1 -lpthread \
		-DDBUS_INSIDE_DBUS_H -DDBUS_DISABLE_ASSERT

run:
	./monitor --profile --system "path='/org/freedesktop/locale1', interface='org.freedesktop.DBus.Properties', member='GetAll'" "path='/org/freedesktop/hostname1', interface='org.freedesktop.DBus.Properties', member='GetAll'"

run1:
	./monitor --profile --session "type='signal', path='/org/mpris/MediaPlayer2', interface='org.freedesktop.DBus.Properties', member='PropertiesChanged'" "type='method_call', path='/org/gnome/Shell/Introspect', interface='org.gnome.Shell.Introspect', member='RunningApplicationsChanged'"
