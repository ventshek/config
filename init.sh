# init, stage one
# Directories
disk=/dev/sda
efi=/dev/sda2
dev=/dev/sda3
partition=/dev/mapper/cryptlvm
volgroup=gg
swap=/dev/gg/swap
root_dev=/dev/gg/root
# Mount points
mnt=/mnt
efi_dir=/mnt/efi
fstabdir=/mnt/etc/fstab
# Script
script=init.sh
# Initial Pacman setup
pacman --quiet --noprogressbar --noconfirm -Sy wipe wget
echo -n "Enter your luks2 password [ENTER]: "
read luks1
# Fill with random data
# dd if=/dev/urandom of="$disk" bs=4k status=progress
# Wipe the drive
# wipe /dev/sda status=progress
# Partition the drives
sfdisk --quiet --force -- "$disk" <<-'EOF'
    label:gpt
    type=21686148-6449-6E6F-744E-656564454649,size=1MiB,attrs=LegacyBIOSBootable,name=bios_boot
    type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B,size=512MiB
    type=0FC63DAF-8483-4772-8E79-3D69D8477DE4
EOF
echo "************************Initial Partitioning Complete************************"
# Setup Luks
echo -en "$luks1" | cryptsetup luksFormat --type luks1 --use-random -S 1 -s 512 -h sha512 -i 5000 "$dev"
# Open new partition
echo -en "$luks1" | cryptsetup luksOpen "$dev" cryptlvm
# Create physical volume
pvcreate "$partition"
# Create volume group
vgcreate "$volgroup" "$partition"
# Create a 512MB swap partition
lvcreate -C y -L1G "$volgroup" -n swap
# Use the rest of the space for root
lvcreate -l '+100%FREE' "$volgroup" -n root
# Format swap
mkswap -- "$swap"
# Format root
mkfs.ext4 -q -L -- "$root_dev"
# Format EFI
mkfs.fat -F32 -- "$efi"
# Mount all disks
mount -- "$root_dev" "$mnt"
mkdir -- "$efi_dir"
swapon -- "$swap"
mount -- "$efi" "$efi_dir"
echo "************************All Partitioning Complete************************"
# Pacstrap all packages
pacstrap "$mnt" --quiet --noprogressbar --noconfirm base linux-lts efibootmgr base-devel efitools linux-lts-headers go linux-firmware mkinitcpio lvm2 htop wget nano torbrowser-launcher e2fsprogs tor nyx vi git xf86-video-vesa xfce4 xfce4-goodies sddm network-manager-applet dhcpcd wpa_supplicant grub sudo fwbuilder intel-ucode virtualbox virtualbox-host-dkms
# Generate fstab
genfstab -U "$mnt" >> "$fstabdir"
# Remove script
rm "$script"
# Setup second script
wget https://github.com/ventshek/i/raw/main/innit.sh
mv innit.sh /mnt
# Remove Bash history
history -c
# Print the password for disk
echo "Disk Password = $luks1"

echo '- Running additional setup in chroot.'
arch-chroot -- "$mount_dir" /bin/bash -s -- "$loop_dev" <<-'EOS'
	set -eEuo pipefail
	trap 'echo "Error: \`$BASH_COMMAND\` exited with status $?"' ERR
	echo '-- Configuring time.'
	ln -sf /usr/share/zoneinfo/UTC /etc/localtime
	gawk -i assert -i inplace '
		/^#NTP=/ { $0 = "NTP=metadata.google.internal"; ++f }
		{ print } END { assert(f == 1, "f == 1") }' /etc/systemd/timesyncd.conf
	systemctl --quiet enable systemd-timesyncd.service
	echo '-- Configuring locale.'
	gawk -i assert -i inplace '
		/^#en_US\.UTF-8 UTF-8\s*$/ { $0 = substr($0, 2); ++f }
		{ print } END { assert(f == 1, "f == 1") }' /etc/locale.gen
	locale-gen
	echo 'LANG=en_US.UTF-8' > /etc/locale.conf
	echo '-- Configuring journald.'
	gawk -i assert -i inplace '
		/^#ForwardToConsole=/ { $0 = "ForwardToConsole=yes"; ++f }
		{ print } END { assert(f == 1, "f == 1") }' /etc/systemd/journald.conf
	echo '-- Configuring ssh.'
	gawk -i assert -i inplace '
		/^#PasswordAuthentication / { $0 = "PasswordAuthentication no"; ++f1 }
		/^#PermitRootLogin / { $0 = "PermitRootLogin no"; ++f2 }
		{ print } END { assert(f1 * f2 == 1, "f == 1") }' /etc/ssh/sshd_config
	systemctl --quiet enable sshd.service
	echo '-- Configuring pacman.'
	curl --silent --show-error -o /etc/pacman.d/mirrorlist \
		'https://archlinux.org/mirrorlist/?country=all&ip_version=4&use_mirror_status=on'
	gawk -i assert -i inplace '
		/^#Server / { $0 = substr($0, 2); ++f }
		{ print } END { assert(f > 0, "f > 0") }' /etc/pacman.d/mirrorlist
	cat <<-'EOF' > /etc/systemd/system/pacman-init.service
		[Unit]
		Description=Pacman keyring initialization
		ConditionDirectoryNotEmpty=!/etc/pacman.d/gnupg
		[Service]
		Type=oneshot
		RemainAfterExit=yes
		ExecStart=/usr/bin/pacman-key --init
		ExecStart=/usr/bin/pacman-key --populate archlinux
		[Install]
		WantedBy=multi-user.target
	EOF
	systemctl --quiet enable pacman-init.service
	echo '-- Enabling other services.'
	systemctl --quiet enable dhclient@eth0.service growpartfs@-.service
	echo '-- Configuring initcpio.'
	gawk -i assert -i inplace '
		/^MODULES=/ { $0 = "MODULES=(virtio_pci virtio_scsi sd_mod ext4)"; ++f1 }
		/^BINARIES=/ { $0 = "BINARIES=(fsck fsck.ext4)"; ++f2 }
		/^HOOKS=/ { $0 = "HOOKS=(base modconf)"; ++f3 }
		{ print } END { assert(f1 * f2 * f3 == 1, "f == 1") }' /etc/mkinitcpio.conf
	gawk -i assert -i inplace '
		/^PRESETS=/ { $0 = "PRESETS=(default)"; ++f }
		/#?fallback_/ { next }
		{ print } END { assert(f == 1, "f == 1") }' /etc/mkinitcpio.d/linux.preset
	rm /boot/initramfs-linux-fallback.img
	mkinitcpio --nocolor --preset linux
	echo '-- Configuring grub.'
	grub-install --target=i386-pc -- "$1"
	cat <<-'EOF' > /etc/default/grub
		# GRUB boot loader configuration
		GRUB_CMDLINE_LINUX="console=ttyS0,38400n8 net.ifnames=0 elevator=noop scsi_mod.use_blk_mq=Y"
		GRUB_PRELOAD_MODULES="part_gpt part_msdos"
		GRUB_TIMEOUT=0
		GRUB_DISABLE_RECOVERY=true
	EOF
	grub-mkconfig -o /boot/grub/grub.cfg
EOS
