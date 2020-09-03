<p align="center">
<b>ZcaTool</b> is tool used to compress Nintendo Switch Formats (NCA/NSP/XCI) using the <a href="https://github.com/zraorg/ZRA">ZRA</a> compression library.
<br>
<a href="https://github.com/Xpl0itR/XcaTool/actions"><img align="center" alt="ZCATool Build" src="https://github.com/Xpl0itR/XcaTool/workflows/.github/workflows/build.yml/badge.svg"/></a>
</p>

***
### Usage
```
Usage: ZcaTool(.exe) [options] <path>
Options:
  -h, --help                 Show this message and exit
  -v, --dev=VALUE            Load production keys as development keys (optional)
  -p, --prodkeys=VALUE       Path to a file containing switch production keys. (optional)
  -t, --titlekeys=VALUE      Path to a file containing switch title keys. (optional)
  -l, --level=VALUE          zStd compression level used to compress the file.
  -f, --framesize=VALUE      Size of a frame used to split a file.
  -o, --output=VALUE         The directory to output the compressed file. (Defaults to the same dir as input file)
```
***
### Format
#### ZCA
ZCA is a plaintext [NCA](https://switchbrew.org/wiki/NCA_Format) compressed using ZRA.
#### ZSP
ZSP files are just renamed [NSP](https://switchbrew.org/wiki/NCA_Format#PFS0) files. They're used to signify to a user that it contains ZCA files. ZSP files can be mixed with NCA files in the same container.
#### ZCI
ZCI files are just renamed [XCI](https://switchbrew.org/wiki/Gamecard_Format) files. They're used to signify to a user that it contains ZCA files. ZCI files can be mixed with NCA files in the same container.
***
### License
We use a simple 3-clause BSD license located at [LICENSE](LICENSE.md) for easy integration into projects while being compatible with the libraries we utilize