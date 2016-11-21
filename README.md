# camflow-provenance-lib

## Version

| Library version | Date       |
| --------------- | ---------- |
| 0.1.13          | N/A        |
| 0.1.12          | 14/11/2016 |
| 0.1.11          | 11/11/2016 |
| 0.1.10          | 28/10/2016 |
| 0.1.9           | 19/10/2016 |
| 0.1.8           | 04/10/2016 |
| 0.1.7           | 19/09/2016 |
| 0.1.6           | 02/09/2016 |
| 0.1.5           | 18/08/2016 |
| 0.1.4           | 18/08/2016 |
| 0.1.3           | 08/08/2016 |
| 0.1.2           | 26/05/2016 |
| 0.1.1           | 03/04/2016 |
| 0.1.0           | 28/03/2016 |

### v0.1.13
```
- Replace "version" by "version_activity" and "version_entity".
```

### v0.1.12
```
- Fix bug in the command line tool (--track-file --track-process not working).
```

### v0.1.11
```
- Does not taint attribute if no taint is set.
- Relation and node types recorded as string.
- Add support for tracking on socket connect and bind.
- Propagate always imply track.
- Clarify command line tool.
- Add interface to set process tracking options.
- 64 bits integers as string in the JSON.
- Add a callback per relation types (none for agents related thing at this point).
- Rework for 64 bits types.
```

### v0.1.10
```
- Guarantee machine id is properly set.
- Add pid and vpid attribute to task JSON serialisation.
```

### v0.1.9
```
- Private mmaped files now appear as separate nodes, connected to the mmaped file by a create relationship.
- Add offset to relation if file info is set.
- Jiffies attribute in JSON output.
```

### v0.1.8
```
- Changed attribute name cf:parent_id -> cf:hasParent.
- Add infrastructure to deal with IPv4 packet provenance.
- Added prov:label elements.
```

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
