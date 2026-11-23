# ry-spm

A personal secure password manager for organizing and protecting private accounts and credentials.

## Purpose

Manager is intended to help an individual manage credentials for services and resources such as email, websites, banks, computers, systems, and apps. Users can organize entries with account categories that are customizable and configurable to fit their needs.

## Security design

The design uses a hierarchy of keys so that each stored item can be encrypted with its own data-encryption key:

1. The user's master passphrase is used to derive a **root key**.
2. The root key is used to derive a **data key** and **mac key**.
3. The root key is used to derive a **info key** to protect the meta.
4. A random **data-encryption key (DEK)** is generated for each item.
5. The DEK is wrapped (encrypted) with the data key.

Conceptually, storage contains encrypted item data and the corresponding wrapped DEK. To access an item, the application derives the key hierarchy from the user's passphrase, unwraps the DEK, and decrypts the item.

## Account organization

Categories are intended to be user-configurable, rather than limited to a fixed set. For example, a user could create categories such as:

- Email
- Websites
- Banking
- Systems
- Applications
- Others

## Security considerations

A strong, master passphrase is important. If it is lost, recovery may not be possible. Anyone with access to the master passphrase and the encrypted data may be able to access the stored credentials.

A strong, safe backup storage is important. If the original file is lost, damaged, or the device fails, backups can used to recover data. Backups can be saved to separate storage, such as a removable USB drive, an external disk, or a network disk, and protect backup media and network storage from unauthorized access. A backup contains sensitive data, even when the vault is encrypted.

## Usage

### spm init

```bash
# create new vault
spm init
# create new vault with aes or sm4 algorithm suite
spm init --alg=aes --category=email --vault=my-email
spm init --alg=sm4 --category=sites --vault=my-sites
```

### spm mock

Generate mock file for the vault, the out is `mock-<category>.json` default.

```bash
# output mock-email.json
spm mock --vault=my-email
# output email-account.json
spm mock --vault=my-email --out=email-account.json
```

### spm add

Add a new password item into the vault, it will be encrypted and then saved.

```bash
# edit the mock file with real data and then execute command
spm add --vault=my-email --in=mock-email.json
```

### spm del

Delete some passwords from the vault by labels, it will out `<category>-<label>.json` if `--pop` used.

```bash
# just delete
spm del --vault=my-email --label=demo1,demo2
# delete and then out email-demo1.json and email-demo2.json
spm del --vault=my-email --label=demo1,demo2 --pop
```

### spm info

Display the summary information of the vault, include all item's label.

```bash
spm info --vault=my-email
```

### spm show

Display the detail information of the vault's item, include the password.

```bash
# default all items
spm show --vault=my-email
# special items
spm show --vault=my-email --label=demo1,demo2
```

### spm update

Update the vault's item information if it exist, it will remain old password if `--his` used.

```bash
spm update --vault=my-email --from=mock-email.json
# remain histroy password
spm update --vault=my-email --from=mock-email.json --his
```
