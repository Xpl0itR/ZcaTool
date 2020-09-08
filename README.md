<p align="center">
<b>ZcaTool</b> is tool used to compress Nintendo Switch Formats (NCA/NSP/XCI) using the <a href="https://github.com/zraorg/ZRA">ZRA</a> compression library. The <a href="https://github.com/zraorg/ZRA.NET">ZRA.NET</a> wrapper library is used here.
<br>
<a href="https://github.com/Xpl0itR/XcaTool/actions"><img align="center" alt="ZCATool Build" src="https://github.com/Xpl0itR/ZcaTool/workflows/ZcaTool%20Build/badge.svg"/></a>
</p>

***
### Usage
```
Usage: ZcaTool(.exe) [options] <path>
Options:
  -h, --help                 Show this message and exit
  -v, --dev=VALUE            Load production keys as development keys (optional)
  -p, --prodkeys=VALUE       Path to a file containing switch production keys. (optional)
  -k, --titlekeys=VALUE      Path to a file containing switch title keys. (optional)
  -l, --level=VALUE          zStd compression level used to compress the file.
  -f, --framesize=VALUE      Size of a frame used to split a file.
  -o, --output=VALUE         The directory to output the compressed file. (Defaults to the same dir as input file)
  -t, --temp=VALUE           The directory to use for storing temp files. (Defaults to OS temp)
```
***
### Format
#### Files
| Original | Compressed |
|-|-|
| [NCA](https://switchbrew.org/wiki/NCA_Format) | ZCA |
| [NSP](https://switchbrew.org/wiki/NCA_Format#PFS0) | ZSP |
| [XCI](https://switchbrew.org/wiki/Gamecard_Format) | ZCI |
- ZCA is a plaintext NCA compressed using ZRA. It also contains a ZCA Header which is located in the ZRA Metadata Section
- ZSP/ZCI files are functionally identical to NSP/XCI files, but have been renamed to signify they contain ZCA files.

#### ZCA Header
| Offset | Size | Description |
|-|-|-|
| 0x0 | 0x4 | "ZCA0" Magic (ASCII) |
| 0x4 | 0x1 | Section Count |
| 0x5 | 0x19 * Section Count | [Section Info](#section-info) Array |

##### Section Info
| Offset | Size | Description |
|-|-|-|
| 0x0 | 0x8 | Offset (Int64) |
| 0x8 | 0x8 | Size (Int64) |
| 0x10 | 0x1 | Encryption Type |
| 0x11 | 0x8 | AES Counter (UInt64) |

***
### License
We use a simple 3-clause BSD license located at [LICENSE](LICENSE.md) for easy integration into projects while being compatible with the libraries we utilize