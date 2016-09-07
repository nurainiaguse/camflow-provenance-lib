# camflow-provenance-lib

## Version

| Library version | Kernel version | Date       |
| --------------- |----------------| ---------- |
| 0.1.7           | 4.4.19         | N/A        |
| 0.1.6           | 4.4.19         | 02/09/2016 |
| 0.1.5           | 4.4.16         | 18/08/2016 |
| 0.1.4           | 4.4.16         | 18/08/2016 |
| 0.1.3           | 4.4.6          | 08/08/2016 |
| 0.1.2           | 4.4.6          | 26/05/2016 |
| 0.1.1           | 4.4.6          | 03/04/2016 |
| 0.1.0           | 4.2.8          | 28/03/2016 |

### v0.1.7
```
- Adding API to manipulate taint.
```

### v0.1.6
```
- Rework how tracking propagation work.
- Added utils function for compression + encoding.
- Refactor code relating to relay.
```


### v0.1.5

```
- Fix bug when reading from relay.
```


### v0.1.4

```
- Allow to set tracking options on a file.
- Adding function to flush relay buffer.
- Fixing polling bug, that used a very large amount of CPU through busy wait.
- Edge renamed relation to align with W3C PROV model.
- Examples moved to https://github.com/CamFlow/examples.
- Install library to /usr/local
- Filter related prototypes now in provenancefilter.h
- Callbacks to filter provenance data in userspace.
- camflow-prov -v print version of CamFlow LSM.
```

### v0.1.3

```
- Added a command line tool to configure provenance.
- Provide functionality to create JSON output corresponding to chunk of the graph.
- Aligning with W3C Prov JSON format.
```

### v0.1.2

```
- Added functions to serialize row kernel data to json.
- Added a function to verify the presence of the IFC module in the kernel.
```

### v0.1.1

```
- IFC Security context recorded in audit.
```

### v0.1.0

```
- Initial release.
```
