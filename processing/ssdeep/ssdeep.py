import os

from bson.objectid import ObjectId
from fame.common import constants
from fame.core.analysis import Analysis
from fame.core.file import File
from fame.core.module import ProcessingModule, ModuleInitializationError

from ..docker_utils import HAVE_DOCKER, docker_client, docker


class SSDeep(ProcessingModule):
    HASHES_FILE_NAME = "ssdeep_hashes.txt"
    HASHES_FILE = os.path.join(constants.VENDOR_ROOT, HASHES_FILE_NAME)
    HASHES_FILE_HEADER = "ssdeep,1.1--blocksize:hash:hash,filename\n"
    CONTAINER_IMAGE = "fame/ssdeep"
    HASH_KEY = "hash"
    MATCHES_KEY = "matches"

    name = "ssdeep"
    description = "Compute and compare context triggered piecewise hashes (CTPH)."

    def initialize(self):
        # Make sure docker is available
        if not HAVE_DOCKER:
            raise ModuleInitializationError(self, "Missing dependency: docker")
        self.results = dict()
        return True

    def get_hash(self):
        file_id = File.get_collection().find_one({"filepath": self.target})["_id"]
        for analysis in Analysis.get_collection().find({"file": file_id}):
            if self.name in analysis["results"].keys():
                return analysis["results"][self.name][self.HASH_KEY]

        return self.calculate_hash(file_id)

    def calculate_hash(self, file_id):
        output = docker_client.containers.run(
            self.CONTAINER_IMAGE,
            f"-bc {file_id}",
            volumes={self.target: {"bind": f"/data/{file_id}", "mode": "ro"}},
            stderr=False,
            remove=True,
        ).decode("UTF-8")

        hash_line = output.splitlines()[-1]

        if not os.path.exists(self.HASHES_FILE):
            self.create_hashes_file()
        with open(self.HASHES_FILE, "a") as f:
            f.write(hash_line + "\n")

        return hash_line.split(",")[0]

    def create_hashes_file(self):
        if not os.path.exists(constants.VENDOR_ROOT):
            os.mkdir(constants.VENDOR_ROOT)

        with open(self.HASHES_FILE, "w") as f:
            f.write(self.HASHES_FILE_HEADER)

    def get_matches(self):
        output = docker_client.containers.run(
            self.CONTAINER_IMAGE,
            f"-m {self.HASHES_FILE_NAME} target.file",
            volumes={
                self.target: {"bind": "/data/target.file", "mode": "ro"},
                self.HASHES_FILE: {
                    "bind": f"/data/{self.HASHES_FILE_NAME}",
                    "mode": "ro",
                },
            },
            stderr=False,
            remove=True,
        ).decode("UTF-8")

        matches = []
        for line in output.splitlines():
            file_id = line.split(" ")[-2].split(":")[-1]
            file_dict = File.get_collection().find_one({"_id": ObjectId(file_id)})
            score = int(line.split(" ")[-1].replace("(", "").replace(")", ""))
            match = {"file": file_dict, "score": score}
            if match not in matches and score < 100:
                matches.append(match)

        return matches

    def each_with_type(self, target, file_type):
        if file_type != "url":
            self.target = target
            self.results[self.HASH_KEY] = self.get_hash()
            self.results[self.MATCHES_KEY] = self.get_matches()

        return self.results["hash"] is not None
