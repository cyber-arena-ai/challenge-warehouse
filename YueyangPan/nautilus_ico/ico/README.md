# ico #

`ico` is a service for manipulating Haiku Vector Image Format (HVIF) files. HVIF is a real image format whose [reference implementation](https://github.com/haiku/haiku/tree/e32d782cb46130f314d737d96d5bb3ddaf5b1c87/src/libs/icon) is within the Haiku operating system. Using resources like Leah Hanson's awesome [blog post](http://blog.leahhanson.us/post/recursecenter2016/haiku_icons.html) from 2016 outlining how the format works, I built a basic, network-ready version of Haiku's Icon-O-Matic application.

Because I like exploring different programming languages (and finding ways to frustrate CTF players), I wrote the entire service in Object Pascal. It's a great and simple language, but it's unfortunately got pretty awful tooling by modern standards. The commercial alternative to FreePascal, Embarcadero's Delphi, would've cost me over $3399 USD here in 2025 in order to implement this challenge. This seems super reasonable in an environment where compilers like `clang` and languages like Rust, Go, and even Crystal (which I used for my DEF CON qualifier challenge) exist, so I'm sure overall usage of Object Pascal will start trending upward again very soon.


## Challenge Service ##

The service is implemented entirely in Object Pascal and the source can be found in the `service/` directory inside this repository. The `Dockerfile` here at the top level specifies how to build it and prepare it for running.

The service consists of a single, statically-linked executable called `ico`. As part of building the service, a small unit test application also builds and runs through a small set of unit tests to ensure basic functionality works. These tests are only copied into the build environment, not the deployment environment.

The service has multiple bugs in it, one of which is simpler and should be possible to quickly find with a fuzzer. My hope is that this causes teams to start scoring and patching quickly, but still have ways to get points out of the challenge beyond the initial vulnerability they're likely to find.

### Building ###

To build the challenge service and its containerized deployment environment, do:

```sh
make docker
```

### Running ###

To run the challenge service, do:

```sh
make run
```


## Challenge Poller ##

The poller for the service is used to ensure that teams don't patch the service in a way that would restrict intended functionality. The poller can also be used to ensure a given deployment is working properly. It was originally written in Ruby, but re-implemented in Python (boo, hiss) to leverage the Nautilus Institute polling library to make things easier for our fabulous team members doing infrastructure work.

### Building ###

To build the challenge poller and its containerized deployment environment, do:

```sh
make poller
```

### Running ###

To run the challenge poller, do:

```sh
make poller-run
```
