from flask import Flask, render_template, request, redirect
import hashlib

app = Flask(__name__)

hashlib_md5 = hashlib.md5
hashlib_sha1 = hashlib.sha1
hashlib_sha224 = hashlib.sha224
hashlib_sha256 = hashlib.sha256


md5 = "5d41402abc4b2a76b9719d911017c592"
sha1 = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
sha224 = "ea09ae9cc6768c50fcee903ed054556e5bfc8347907f12598aa24193"
sha256 = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"


def identify_hash(hashed_value):
    if hashed_value == "exit":
        sys.exit()
    if len(hashed_value) == len(md5):
        return hashlib_md5
    elif len(hashed_value) == len(sha1):
        return hashlib_sha1
    elif len(hashed_value) == len(sha224):
        return hashlib_sha224
    elif len(hashed_value) == len(sha256):
        return hashlib_sha256
    else:
        return None


def crack(hash_type, hash_value):
    with open("password_list.txt" , "r") as file:
        for line in file:
            global word
            for word in line.split():
                hash_object = hash_type(f"{word}".encode('utf-8'))
                hashed = hash_object.hexdigest()
                # print(f"md5: {hashed}")
            if hash_value == hashed:
                break
        else:
            word = "Couldn't Crack the Hash"


@app.route('/')
def hello_world():
    return render_template("index.html")


@app.route("/check_hash", methods=['POST'])
def check_hash():
    if request.method == "POST":
        hash_value = request.form["hash_value"]
        identified_hash = identify_hash(hash_value)
        if identified_hash != None:
            crack(identified_hash, hash_value)
            if identified_hash == hashlib_md5:
                display_hash_type = "MD5"
            elif identified_hash == hashlib.sha1:
                display_hash_type = "SHA1"
            elif identified_hash == hashlib.sha224:
                display_hash_type = "SHA224"
            elif identified_hash == hashlib.sha256:
                display_hash_type = "SHA256"
            return render_template("result.html", cracked_hash=word, hash_type=display_hash_type)
        else:
            return render_template("error.html")


if __name__ == '__main__':
    app.run()