import hashlib
import os
from typing import Any, Literal

import typer
from rich.console import Console
from rich.table import Table
from tqdm import tqdm


class Hasher:
    HASH_ALGORITHM_TYPE = Literal["md5", "sha1", "sha256", "sha512"]

    support_hash_algorithms: list[HASH_ALGORITHM_TYPE] = ["md5", "sha1", "sha256", "sha512"]
    default_hash_algorithms: list[HASH_ALGORITHM_TYPE] = support_hash_algorithms

    def __init__(self) -> None:
        self.console: Console = Console()

    @staticmethod
    def _shorten_middle_text(text: str, text_max_len: int = 50) -> str:
        if len(text) <= text_max_len:
            return text
        part = (text_max_len - 3) // 2
        return f"{text[:part]}...{text[-part:]}"

    def _validate_hash_algorithms(self, hash_algorithms: list[HASH_ALGORITHM_TYPE]) -> list[HASH_ALGORITHM_TYPE]:
        return [
            i if i in self.support_hash_algorithms
            else (_ for _ in ()).throw(ValueError(f"Unsupported hash_algorithm: {i}"))
            for i in hash_algorithms
        ]

    @staticmethod
    def _get_tqdm_params(desc: str) -> dict[str, Any]:
        return dict(
            unit="B",
            unit_scale=True,
            unit_divisor=1024,
            desc=desc,
            mininterval=0.1,
            dynamic_ncols=True,
            bar_format="{l_bar}{bar} {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]"
        )

    def hash_file(
            self,
            file_path: str,
            hash_algorithms: list[HASH_ALGORITHM_TYPE] | None = None,
            chunk_size_mb: int = 8
    ) -> dict[str, str]:
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"Not found file_path: {file_path}")

        if hash_algorithms is None:
            hash_algorithms = self.default_hash_algorithms

        total = os.path.getsize(file_path)
        desc = f"[Hasher Algorithms ({', '.join(hash_algorithms)})] {self._shorten_middle_text(file_path)}"
        chunk_size = chunk_size_mb * 1024 * 1024

        hash_algorithms = self._validate_hash_algorithms(hash_algorithms)
        hashers = {i: getattr(hashlib, i)() for i in hash_algorithms}

        with open(file_path, "rb") as f, tqdm(total=total, **self._get_tqdm_params(desc)) as pbar:
            while chunk := f.read(chunk_size):
                for h in hashers.values():
                    h.update(chunk)
                pbar.update(len(chunk))

        return {i: h.hexdigest() for i, h in hashers.items()}

    def hash_text(
            self,
            text: str,
            hash_algorithms: list[HASH_ALGORITHM_TYPE] | None = None,
            chunk_size_mb: int = 8
    ) -> dict[str, str]:
        if hash_algorithms is None:
            hash_algorithms = self.default_hash_algorithms

        data = text.encode("utf-8")
        total = len(data)
        desc = f"[Hasher Algorithms ({', '.join(hash_algorithms)})] {self._shorten_middle_text(text)}"
        chunk_size = chunk_size_mb * 1024 * 1024

        hash_algorithms = self._validate_hash_algorithms(hash_algorithms)
        hashers = {i: getattr(hashlib, i)() for i in hash_algorithms}

        with tqdm(total=total, **self._get_tqdm_params(desc)) as pbar:
            for i in range(0, total, chunk_size):
                chunk = data[i:i + chunk_size]
                for h in hashers.values():
                    h.update(chunk)
                pbar.update(len(chunk))

        return {i: h.hexdigest() for i, h in hashers.items()}

    def _display_table(self, rows: list[tuple[str, str, str, str]]) -> None:
        table = Table(title=f"[Hasher Result]")
        table.add_column("Hash Algorithm", style="yellow")
        table.add_column("Type", style="magenta")
        table.add_column("Input", style="cyan", overflow="fold")
        table.add_column("Hash", style="green")
        for row in rows:
            table.add_row(row[0], row[1], self._shorten_middle_text(row[2]), row[3])
        self.console.print("\n")
        self.console.print(table)

    def cli(self) -> None:
        app = typer.Typer(help="Hasher - compute hashes for files or text (--file or --text)")

        @app.command(help=f"Compute hash (default hash_algorithms: {', '.join(self.default_hash_algorithms)})")
        def main(
                input: str = typer.Argument(None, help="Input file or text to hash"),  # noqa
                file: str = typer.Option(None, "--file", "-f", help="File to hash"),
                text: str = typer.Option(None, "--text", "-t", help="Text to hash"),
                hash_algorithm: str = typer.Option(
                    None,
                    "--hash-algorithm", "-h",
                    help=f"Comma separated hash_algorithms (default: {', '.join(self.default_hash_algorithms)})"
                ),
                chunk_size: int = typer.Option(8, "--chunk-size", "-c", help="Chunk size in MB"),
        ) -> None:
            if input and not (file or text):
                file = input if os.path.isfile(input) else None
                text = input if not file else None

            if not file and not text:
                typer.echo("Error: provide --file or --text")
                raise typer.Exit(code=1)

            if file and text:
                typer.echo("Error: choose only one of --file or --text")
                raise typer.Exit(code=1)

            try:
                hash_algorithms: list[Hasher.HASH_ALGORITHM_TYPE] = (
                    [i.strip() for i in hash_algorithm.split(",")] if hash_algorithm else self.default_hash_algorithms
                )

                results = self.hash_file(file, hash_algorithms, chunk_size) if file else \
                    self.hash_text(text, hash_algorithms, chunk_size)

                rows = [(k, "file" if file else "text", file or text, v) for k, v in results.items()]

                self._display_table(rows)

            except Exception as e:
                typer.secho(f"Error: {e}", fg=typer.colors.RED)
                raise typer.Exit(code=1)

        app()


if __name__ == "__main__":
    Hasher().cli()
