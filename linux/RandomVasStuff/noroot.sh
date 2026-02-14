read -p "Enter User:" user
if [ "$user" == "" ]; then
  echo "No user entered. Exiting."
  exit 1
fi
if ! id -u "$user" >/dev/null 2>&1; then
  echo "User '$user' does not exist. Exiting."
  exit 1
else 
  echo "User '$user' exists."
fi
gpasswd -d "$user" wheel

if [$? -eq 0 ]; then
  echo "User '$user' hasthd been oblitorated."
else
  echo "Failed to remove user '$user' from wheel group. Exiting."
  exit 1
fi
#verify user does not have sudo access 
if sudo -lU "$user" >/dev/null 2>&1; then
  echo "User '$user' guess it didn't work still has sudo."
else
  echo "User '$user' L + ratio the job is done."
fi

