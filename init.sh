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
# Pacman packages
basic="base linux-lts efibootmgr base-devel efitools linux-lts-headers linux-firmware mkinitcpio lvm2"
extra="top htop wget nano torbrowser-launcher e2fsprogs tor nyx vi git"
gfx="xf86-video-vesa xfce4 xfce4-goodies sddm network-manager-applet"
other="dhcpcd wpa_supplicant grub sudo fwbuilder intel-ucode virtualbox virtualbox-host-dkms"
# Initial Pacman setup
pacman --noconfirm -Sy
pacman --noconfirm -S wipe
echo -n "Enter your luks2 password [ENTER]: "
read luks2
# Fill with random data
dd if=/dev/urandom of="$disk" bs=4k status=progress
# Wipe the drive
wipe /dev/sda status=progress
# Partition the drives
sfdisk --quiet -- "$disk" <<-'EOF'
    label:gpt
    type=21686148-6449-6E6F-744E-656564454649,size=1MiB,attrs=LegacyBIOSBootable,name=bios_boot
    type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B,size=512MiB
    type=0FC63DAF-8483-4772-8E79-3D69D8477DE4
EOF
# Setup Luks
echo -en "$luks2" | cryptsetup luksFormat --type luks2 --use-random -S 1 -s 512 -h sha512 -i 5000 "$dev"
# Open new partition
echo -en "$luks2" | cryptsetup luksOpen "$dev" cryptlvm
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
# Mount root
mount -- "$root_dev" "$mnt"
# Make efi directory
mkdir -- "$efi_dir"
# Mount swap
swapon -- "$swap"
# Mount EFI
mount -- "$efi" "$efi_dir"
# Pacstrap
pacstrap "$mnt" "$basic" "$gfx" "$other" "$extra"
# Generate fstab
genfstab -U "$mnt" >> "$fstabdir"
# Remove script
rm "$script"
# Remove Bash history
history -c
# Print the password for disk
echo "Luks2=$luks2"
