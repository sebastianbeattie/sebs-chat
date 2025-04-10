# Seb's Chat

Used to send encrypted text messages to people. Very simple. Probably not very secure.

## Example Config

```json
{
    "userId": "Seb",
    "selfKeyConfig": {
        "private": "./private/private.key",
        "public": "./private/public.key",
        "signingPrivate": "./private/signing_private.key",
        "signingPublic": "./private/signing_public.key"
    },
    "externalKeysDir": "./keys"
}
```

## Creating your keys

First create a config.json file like the one above. Then, simply run:

```bash
./sebs-chat -cmd=create
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
./sebs-chat -cmd=encrypt -input=message.json
```

And you will receive a JSON output. You can share this freely with anyone. If you want to capture the JSON to a file, run:

```bash
./sebs-chat -cmd=encrypt -input=message.json > encrypted.json
```

Which will output the encrypted message to a file called `encrypted.json`

## Decrypting a message

If you have received a message, you can decrypt it by saving the JSON to a file, and then running the decrypt command:

```bash
./sebs-chat -cmd=decrypt -input=encrypted.json
```

You should see an output like this:

```
User: An unencrypted message
```