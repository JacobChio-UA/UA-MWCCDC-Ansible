# 1. Enable the developer repository (if not already enabled)
dnf install oracle-linux-developer-release -y
# 2. Install Ansible
dnf install ansible git -y
# 3. Verify installation
ansible --version
git clone https://github.com/cisagov/LME.git
cp ansible.cfg LME/ansible.cfg
cp lme-environment.env LME/config/lme-environment.env
cd LME
./install.sh
cd ..
ansible-playbook -i inventory.yaml linuxPlaybook.yaml