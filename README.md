
<div align="center">
  Ansible Solarwinds Inventory Plugin
  <br />
  <a href="#about"><strong>Explore the docs »</strong></a>
  <br />
  <br />
  <a href="https://github.com/dalrrard/ansible-solarwinds-inventory-plugin/issues/new?assignees=&labels=bug&template=01_BUG_REPORT.md&title=bug%3A+">Report a Bug</a>
  ·
  <a href="https://github.com/dalrrard/ansible-solarwinds-inventory-plugin/issues/new?assignees=&labels=enhancement&template=02_FEATURE_REQUEST.md&title=feat%3A+">Request a Feature</a>
  .
  <a href="https://github.com/dalrrard/ansible-solarwinds-inventory-plugin/issues/new?assignees=&labels=question&template=04_SUPPORT_QUESTION.md&title=support%3A+">Ask a Question</a>
</div>

<div align="center">
<br />

[![Project license](https://img.shields.io/github/license/dalrrard/ansible-solarwinds-inventory-plugin.svg?style=flat-square)](LICENSE)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

[![Pull Requests welcome](https://img.shields.io/badge/PRs-welcome-ff69b4.svg?style=flat-square)](https://github.com/dalrrard/ansible-solarwinds-inventory-plugin/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22)
[![code with love by dalrrard](https://img.shields.io/badge/%3C%2F%3E%20with%20%E2%99%A5%20by-dalrrard-ff1414.svg?style=flat-square)](https://github.com/dalrrard)

</div>

<details open="open">
<summary>Table of Contents</summary>

- [About](#about)
  - [Built With](#built-with)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
- [Usage](#usage)
- [Roadmap](#roadmap)
- [Support](#support)
- [Project assistance](#project-assistance)
- [Contributing](#contributing)
- [Authors & contributors](#authors--contributors)
- [Security](#security)
- [License](#license)

</details>

---

## About

The Ansible Solarwinds Inventory Plugin was built to allow you to use your preexisting Solarwinds NCM inventory information to run Ansible playbooks against. 

### Built With

This project was built and tested using Python 3.9 and Ansible 4.8.0 (ansible-core 2.11.6) though earlier versions should work with minimal to no tweaking.

## Getting Started

### Prerequisites

This plugin currently uses the Cirrus.Nodes table from Solarwinds NCM using the [Solarwinds Information Service (SWIS)](https://github.com/solarwinds/OrionSDK/wiki/About-SWIS). In the future, the ability to pull information from Orion may be added.

### Installation

You can install this plugin in a few ways. The most straightforward is to add the plugin locally as described in [these instructions](https://docs.ansible.com/ansible/latest/dev_guide/developing_locally.html#adding-a-plugin-locally). For convenience, this is how you can add it to your user's home directory in Linux.

```bash
mkdir -p ~/.ansible/plugins/inventory

cd ~/.ansible/plugins/inventory

curl -O https://raw.githubusercontent.com/dalrrard/ansible-solarwinds-inventory-plugin/main/solarwinds.py
```

You can verify that Ansible sees the plugin by running this command:

```bash
ansible-doc -t inventory solarwinds
```

## Usage

To use this plugin, you'll need to create a file named any of these names:
  
  * `solarwinds_inventory.yaml`
  * `solarwinds_inventory.yml`
  * `solarwinds.yaml`
  * `solarwinds.yml`
  
The information below is mandatory information to put in the file.

```yaml
---
plugin: solarwinds
base_url: https://<server-fqdn-or-ip>
username: <vault encrypted username for Solarwinds>
password: <vault encrypted password for Solarwinds>
```

This details all available options.

```yaml
---
plugin: solarwinds
base_url: https://<server-fqdn-or-ip>
username: <vault encrypted username for Solarwinds>
password: <vault encrypted password for Solarwinds>
api_port: 17778
verify_ssl: true
additional_properties:
  - Location
  - OwningGroup
  - Tenant
  - SiteID
```

The `additional_properties` option is a list of column names from `Cirrus.Nodes` that you want to group the inventory by. The plugin automatically retrieves these fields from `Cirrus.Nodes`:

  * `AgentIP`
  * `SysName`
  * `ConnectionProfile`
  * `MachineType`
  * `OSVersion`
  * `OSImage`

It uses `SysName` for the `ansible_host` variable and will attempt to retrieve the `ConnectionProfile` information for each device and set the `ansible_user`, `ansible_password`, and `ansible_become_password` for each device with the information from the associated profile.

You can use the inventory just like any other. This command will print an inventory graph to your screen of all the hosts and groups they belong to.

```bash
ansible-inventory -i solarwinds_inventory.yml --graph --ask-vault-pass
```

## Roadmap

See the [open issues](https://github.com/dalrrard/ansible-solarwinds-inventory-plugin/issues) for a list of proposed features (and known issues).

- [Top Feature Requests](https://github.com/dalrrard/ansible-solarwinds-inventory-plugin/issues?q=label%3Aenhancement+is%3Aopen+sort%3Areactions-%2B1-desc) (Add your votes using the 👍 reaction)
- [Top Bugs](https://github.com/dalrrard/ansible-solarwinds-inventory-plugin/issues?q=is%3Aissue+is%3Aopen+label%3Abug+sort%3Areactions-%2B1-desc) (Add your votes using the 👍 reaction)
- [Newest Bugs](https://github.com/dalrrard/ansible-solarwinds-inventory-plugin/issues?q=is%3Aopen+is%3Aissue+label%3Abug)

## Support

Reach out to the maintainer at one of the following places:

- [GitHub issues](https://github.com/dalrrard/ansible-solarwinds-inventory-plugin/issues/new?assignees=&labels=question&template=04_SUPPORT_QUESTION.md&title=support%3A+)
- Contact options listed on [this GitHub profile](https://github.com/dalrrard)

## Project assistance

If you want to say **thank you** or/and support active development of Ansible Solarwinds Inventory Plugin:

- Add a [GitHub Star](https://github.com/dalrrard/ansible-solarwinds-inventory-plugin) to the project.
- Tweet about the Ansible Solarwinds Inventory Plugin.
- Write interesting articles about the project on [Dev.to](https://dev.to/), [Medium](https://medium.com/) or your personal blog.

Together, we can make Ansible Solarwinds Inventory Plugin **better**!

## Contributing

First off, thanks for taking the time to contribute! Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make will benefit everybody else and are **greatly appreciated**.


Please read [our contribution guidelines](docs/CONTRIBUTING.md), and thank you for being involved!

## Authors & contributors

The original setup of this repository is by [Dalton Rardin](https://github.com/dalrrard).

For a full list of all authors and contributors, see [the contributors page](https://github.com/dalrrard/ansible-solarwinds-inventory-plugin/contributors).

## Security

Ansible Solarwinds Inventory Plugin follows good practices of security, but 100% security cannot be assured.
Ansible Solarwinds Inventory Plugin is provided **"as is"** without any **warranty**. Use at your own risk.

_For more information and to report security issues, please refer to our [security documentation](docs/SECURITY.md)._

## License

This project is licensed under the **GNU General Public License v3**.

See [LICENSE](LICENSE) for more information.
