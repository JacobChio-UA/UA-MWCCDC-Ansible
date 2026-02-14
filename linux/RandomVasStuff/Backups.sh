SDP=("/etc/postfix")
DDP=("/mnt/backup/postfixB")
Dir=("/mnt/backup")
SYD=("/etc/sysconfig")
DOV=("/etc/dovecot")
SCB=("/mnt/backup/sysconfigB")
DOVB=("/mnt/backup/dovecotB")
#making a the directory and doing the stuff ig
if [ ! -d "$Dir" ]; then    
    mkdir -p "$Dir"
fi
cp -r "$SDP" "$DDP"
cp -r "$syd" "$SCB"
cp -r "$DOV" "$DOVB"

