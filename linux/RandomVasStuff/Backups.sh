SDP = ("/etc/postfix")
DDP = ("/mnt/backup/postfixB")
Dir = ("/mnt/backup")
SYD = ("/etc/sysconfig")
DOV = ("/etc/dovecot")
#making a the directory and doing the stuff ig
if [ ! -d "$dir" ]; then    
    mkdir -p "$dir"
fi
cp -r "$SDP" "$DDP"
cp -r "$syd" "/mnt/backup/sysconfigB"
cp -r "$DOV" "/mnt/backup/dovecotB"
