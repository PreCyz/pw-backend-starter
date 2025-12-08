## Inspiration taken from
* [Example Dockerfiles with Two-Step AOT Workflow](https://gist.github.com/ammbra/59aa7cdb776145a227469730020aa5a4)
* [Supercharge your JVM Performance with Project Leyden and Spring Boot](https://www.youtube.com/watch?v=izLzgnMMjbU)

### Commands must be executed from the root of the project.

### Commands to build and generate the AOT cache:

```docker
docker build -f docker/aotgen.Dockerfile --build-arg JAR_FILE=../target/*.jar -t app-aotgen:local .
docker run --name aotgen --rm -e AOT_DIR=/cache -v "$PWD/cache:/cache" app-aotgen:local
```
### Command to run the application with the AOT cache:

```docker
docker build -f docker/deploy.Dockerfile -t app-deploy:local .
docker run -d --name app-deploy -e AOT_DIR=/cache -v "$PWD/cache:/cache" -p 8080 app-deploy:local
```
Or simply run `docker compose -f docker/compose.yml up --build` to achieve the same result.