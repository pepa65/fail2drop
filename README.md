# fail2drop

go build fail2drop.go
sudo cp fail2drop /usr/bin/
sudo cp fail2drop.service /etc/systemd/system/
sudo systemctl enable fail2drop.service
sudo systemctl start fail2drop.service