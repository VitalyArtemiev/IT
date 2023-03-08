docker compose build error:


	failed to solve: rpc error: code = Unknown desc = failed to solve with frontend dockerfile.v0: failed to create LLB definition: failed to authorize: rpc error: code = Unknown desc = failed to fetch anonymous token: Get "https://auth.docker.io/token?scope=repository%3Alibrary%2Fnginx%3Apull&service=registry.docker.io": dial tcp 44.205.64.79:443: i/o timeout

solution:
sudo DOCKER_BUILDKIT=0 docker compose build


volumes:  
  - .dbdata:/var/lib/postgresql/data:z