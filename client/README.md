# Seb's Chat

Used to send encrypted text messages to people. Very simple. Probably not very secure.

## Compiling

Nice and easy. Developed with Go 1.24.1, but lower versions might work.

```
go build
```

## Example Config

```json
{
    "userId": "Seb",
    "selfKeyConfig": {
        "private": "./private/private.key",
        "public": "./private/public.key",
        "signingPrivate": "./private/signing_private.key",
        "signingPublic": "./private/signing_public.key",
        "authToken": "./private/auth_token"
    },
    "serverConfig": {
        "host": "sebschat.myserver.com",
        "port": 80,
        "useTls": true
    },
    "externalKeysDir": "./keys"
}
```

**Note: If you are connecting to a server running on localhost, you probably need to set useTls to false**

## Creating your keys

First create a config.json file like the one above. Then, simply run:

```bash
./sebs-chat keygen
```

And the app will create your key pairs.

## Sharing keys

You should only ever share your public key (`public.key`). Never share your private keys. Your public signing key is bundled into messages for you.

In order to encrypt messages to send to you, you will need to distribute your public key to other users. Send them your `public.key` file.

Upon receipt of a `public.key` file, you will need to put it in a folder **inside your external keys directory, named after their user ID.** For example, if you received a key from Bob, your external keys directory should look like this:

```
keys
  └─Bob
     └─public.key
```

## Encrypting a message

If you have shared your public key and you have received the public keys of the recipients of your message, you're ready to start encrypting! Your message needs to go in a JSON file, structured like this:

```json
{
    "rawText": "Hello, World!",
    "recipients": ["Bob"]
}
```

Your text message goes in the rawText field, and the recipients is a list of user IDs. Any users you want to send a message to, you MUST have their public key saved.

Encrypt your message by running:

```bash
./sebs-chat encrypt --input message.json
```

And you will receive a JSON output. You can share this freely with anyone. If you want to capture the JSON to a file, run:

```bash
./sebs-chat encrypt --input message.json > encrypted.json
```

Which will output the encrypted message to a file called `encrypted.json`

## Decrypting a message

If you have received a message, you can decrypt it by saving the JSON to a file, and then running the decrypt command:

```bash
./sebs-chat decrypt --input encrypted.json
```

You should see an output like this:

```
User: An unencrypted message
```

## Connecting to a server

First, make sure you've registered your user ID on the server:

```bash
./sebs-chat register
```

And then, you can connect to a group by specifying the group name:

```bash
./sebs-chat connect --group MyGroup
```

If you want to create a group, you'll need a JSON file like this:

```json
{
    "groupName": "SebAndCo", // The name of the group
    "groupMembers": ["Seb", "AlsoSeb"], //The users in the group
    "deleteWhenEmpty": false // Delete the group when everyone has left
}
```

And you can send this to the server with:

```bash
./sebs-chat create-group --input group.json
```

You can see what groups you're in by running:

```bash
./sebs-chat list-groups
```

And you can view a specific group by running:

```bash
./sebs-chat group-info --group GroupName
```