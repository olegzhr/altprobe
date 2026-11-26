import os
import sys
import argparse
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

from services.mcp.transports.http import mcp_router
from services.test_api.transports.http import test_api_router
from services.inventory_mock.http import inventory_router


def create_app() -> FastAPI:
    app = FastAPI(
        title="Altprobe Demo Mock",
        description="Safe demo server for /mcp and /test-api traffic",
        version="1.0.0",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(mcp_router)
    app.include_router(test_api_router)
    app.include_router(inventory_router)

    return app


def main():
    parser = argparse.ArgumentParser(description="Altprobe demo mock server")
    parser.add_argument("--host", default="127.0.0.1", help="HTTP server host")
    parser.add_argument("--port", type=int, default=8000, help="HTTP server port")
    parser.add_argument("--data-dir", default=None, help="Data directory for MCP file resources")
    args = parser.parse_args()

    os.environ["MCP_DATA_DIR"] = args.data_dir or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "services", "mcp", "data"
    )

    app = create_app()
    print(f"Demo mock starting on http://{args.host}:{args.port}", file=sys.stderr)
    print("  /mcp      - MCP demo endpoint", file=sys.stderr)
    print("  /test-api - REST demo endpoint", file=sys.stderr)
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
