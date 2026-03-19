# Flagr Docker Image

## Building

```
$ docker build -t flagr .
```

_NOTE_ - The build process takes 5-10 minutes on our development machines.
There are a lot of dependencies to to install and/or build. Be patient.

## Running Flagr

The default command for the docker image is:

```
python -m flagr -c /data/flagr.ini -m \
	monitor=/data/targets,outdir=/data/results
```

We recommend running Flagr with the following command:

```shell
$ docker run -v "$(CTF_DIRECTORY):/data" -it flagr
```

Where `CTF_DIRECTORY` is a directory with a configuration file and a `targets`
directory. After Flagr is started, it will automatically monitor the `targets`
directory for targets to queue or you can manually queue targets as normal at
the REPL. 

The smallest configuration file you can use could be `flagr.ini` like so:

```
[manager]
flag-format=FLAG{.*?}
```

## Issues

The things that do not work when using the Docker container:

* Clipboard

	When Flagr finds a flag, it will not be able to have it automatically
	copied into your clipboard.

* Notifications

	When Flagr finds a flag, it will not be able to send you a desktop
	notification explaining that it solved a challenge.