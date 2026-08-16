import contextlib
import io
import os
import tempfile
import threading
import unittest
from unittest import mock

import downloader
import share_sniffer


class FakeEntry:
    def __init__(self, name, is_directory=False):
        self.name = name
        self.directory = is_directory

    def get_longname(self):
        return self.name

    def is_directory(self):
        return self.directory


class FakeScanConnection:
    def listShares(self):
        return [{"shi1_netname": "public\x00"}]

    def listPath(self, share, path):
        return [FakeEntry("file.txt")]

    def logoff(self):
        pass


class FailingWorkerConnection:
    def listPath(self, share, path):
        raise RuntimeError("simulated directory failure")

    def logoff(self):
        pass


class FakeDownloadConnection:
    def __init__(self, failing_names=()):
        self.failing_names = set(failing_names)
        self.attempts = []

    def getFile(self, share, remote, callback):
        self.attempts.append((share, remote))
        if any(remote.endswith(name) for name in self.failing_names):
            raise OSError("simulated transfer failure")
        callback(b"downloaded")

    def logoff(self):
        pass


class ScannerReliabilityTests(unittest.TestCase):
    def run_with_deadline(self, function):
        result = []
        thread = threading.Thread(target=lambda: result.append(function()), daemon=True)
        thread.start()
        thread.join(timeout=1.0)
        self.assertFalse(thread.is_alive(), "operation did not return before the deadline")
        return result[0]

    def test_all_worker_connections_fail_without_hanging_and_keep_root_results(self):
        output = io.StringIO()

        def run():
            return share_sniffer.write_tree(
                object(),
                "public",
                output,
                False,
                "host: public",
                initial_entries=[FakeEntry("folder", is_directory=True)],
                dir_threads=2,
                connect_func=mock.Mock(side_effect=OSError("connection failed")),
            )

        with contextlib.redirect_stderr(io.StringIO()):
            succeeded = self.run_with_deadline(run)

        self.assertFalse(succeeded)
        self.assertEqual(output.getvalue(), "/folder/\n")

    def test_unexpected_worker_failure_drains_the_queue(self):
        output = io.StringIO()

        def run():
            return share_sniffer.write_tree(
                object(),
                "public",
                output,
                False,
                "host: public",
                initial_entries=[FakeEntry("folder", is_directory=True)],
                dir_threads=1,
                connect_func=FailingWorkerConnection,
            )

        with contextlib.redirect_stderr(io.StringIO()):
            succeeded = self.run_with_deadline(run)

        self.assertFalse(succeeded)
        self.assertEqual(output.getvalue(), "/folder/\n")

    def test_total_target_failure_returns_nonzero(self):
        with tempfile.TemporaryDirectory() as output_dir:
            with mock.patch.object(
                share_sniffer,
                "connect_smb",
                side_effect=OSError("connection failed"),
            ):
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(
                    io.StringIO()
                ):
                    status = share_sniffer.main(
                        ["host.invalid", "--no-pass", "-o", output_dir]
                    )

        self.assertEqual(status, 1)

    def test_successful_target_returns_zero(self):
        with tempfile.TemporaryDirectory() as output_dir:
            with mock.patch.object(
                share_sniffer,
                "connect_smb",
                return_value=FakeScanConnection(),
            ):
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(
                    io.StringIO()
                ):
                    status = share_sniffer.main(
                        ["host.invalid", "--no-pass", "-o", output_dir]
                    )
            files_path = os.path.join(output_dir, "host.invalid", "public", "files.txt")
            with open(files_path, "r", encoding="utf-8") as handle:
                contents = handle.read()

        self.assertEqual(status, 0)
        self.assertEqual(contents, "/file.txt\n")


class DownloaderStatusTests(unittest.TestCase):
    def run_downloader(self, output_dir, connection):
        with mock.patch.object(downloader, "connect_smb", return_value=connection):
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(
                io.StringIO()
            ):
                return downloader.main(
                    [
                        "--paths",
                        "//host/share/one.txt",
                        "--paths",
                        "//host/share/two.txt",
                        "--no-pass",
                        "-o",
                        output_dir,
                    ]
                )

    def test_connection_failure_returns_nonzero(self):
        with tempfile.TemporaryDirectory() as output_dir:
            with mock.patch.object(
                downloader,
                "connect_smb",
                side_effect=OSError("connection failed"),
            ):
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(
                    io.StringIO()
                ):
                    status = downloader.main(
                        [
                            "--paths",
                            "//host/share/file.txt",
                            "--no-pass",
                            "-o",
                            output_dir,
                        ]
                    )

        self.assertEqual(status, 1)

    def test_mixed_transfers_continue_and_return_nonzero(self):
        connection = FakeDownloadConnection(failing_names={"one.txt"})
        with tempfile.TemporaryDirectory() as output_dir:
            status = self.run_downloader(output_dir, connection)
            output_names = os.listdir(output_dir)

        self.assertEqual(status, 1)
        self.assertEqual(len(connection.attempts), 2)
        self.assertEqual(len(output_names), 1)
        self.assertFalse(any(name.endswith(".part") for name in output_names))

    def test_all_successful_transfers_return_zero(self):
        connection = FakeDownloadConnection()
        with tempfile.TemporaryDirectory() as output_dir:
            status = self.run_downloader(output_dir, connection)
            output_names = os.listdir(output_dir)

        self.assertEqual(status, 0)
        self.assertEqual(len(connection.attempts), 2)
        self.assertEqual(len(output_names), 2)
        self.assertFalse(any(name.endswith(".part") for name in output_names))


if __name__ == "__main__":
    unittest.main()
