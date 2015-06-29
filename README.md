# PM_Shredder

A python script to rip / shred emails apart with Yara.

## Contents

* shredder.py - shreds the email
* yara_include.yar - Full set of Yara rules (if attachment exists)
* yara_headers.yar - Slimmed down set of Yara rules to run (if no attachment exists)
* email_contents.yar - Rules around contents of an email (header IP's, body text, domains, etc)
* magic.yar - Magic byte rules
* exe.yar - Rules around exe's and such

## Usage

```
cat email.eml | ./shredder.py
```

## Setup

### Dependancies
* [Yara](http://plusvic.github.io/yara/)
* [Yara Python](http://plusvic.github.io/yara/)
* [SSDEEP python](https://pypi.python.org/pypi/ssdeep)

Example rule:
```
rule example_rule
{
  strings:
    $a1 = "46.165.252.13"
    $a2 = "@peypal.com" nocase
  condition:
    any of them
}
```

Schema:
```
key = randomly generated UUID at runtime
CREATE TABLE email_meta(key varchar, date varchar, e_to varchar, e_from varchar, e_subject varchar, attachment varchar, reporting_mechanism varchar, email varchar);
CREATE TABLE hash_db(key varchar, md5 varchar, sha256 varchar, ssdeep varchar);
CREATE TABLE urls(key varchar, url varchar, cleaned_url varchar);
CREATE TABLE yara_hits(key varchar, hit varchar);
```

Reasoning for splitting them out like this:

There is no easy way to get back to a piece of information if you don't use it like this.
Example: What user received this email with this link? By using this schema, any aspect of an email can get you back to the original (email id(key))


## Installation

### Install System Packages
```
su root
yum update
yum groupinstall "Development tools"
yum install zlib-devel bzip2-devel openssl-devel ncurses-devel
```

### Alternative Install of Python 2.7
```
cd /opt
wget http://www.python.org/ftp/python/2.7.3/Python-2.7.3.tar.bz2
tar xf Python-2.7.3.tar.bz2
cd Python-2.7.3
./configure --prefix=/usr/local
make && make altinstall
```

### Install Yara
```
wget https://github.com/plusvic/yara/archive/2.1.0.tar.gz
cd yara-2.1.0
chmod +x build.sh
./build.sh
sudo make install
```

### Yara python
```
yum install python-devel
cd yara-python
python setup.py build
sudo python setup.py install
python2.7 setup.py build
python2.7 setup.py install
```

### Ssdeep Python Installation (CentOS):
```
su
yum install python-setuptools
easy_install cython
easy_install ssdeep
```

### Verify Installation

Run `python` from the command line, and type `import yara`. If you get an error that looks like this:
```
ImportError: libyara.so.0: cannot open shared object file: No such file or directory
```

Run the following (CentOS):
```
$ sudo echo "/usr/local/lib" >> /etc/ld.so.conf
$ ldconfig
```

Postfix stdin:

Check out this post here: http://stackoverflow.com/questions/8312001/python-postfix-stdin

It is only one line to your `/etc/alias` file: `emailname: "|/path/to/script.py"`

## Contributing

1. Fork it ( https://github.com/x41x41x90/pm_shredder )
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request
