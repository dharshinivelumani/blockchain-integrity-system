import hashlib
import json
from time import time


class Blockchain:

    def __init__(self):

        self.chain = []

        self.create_block(
            previous_hash='0',
            file_hash='Genesis Block'
        )


    # Create New Block
    def create_block(self, previous_hash, file_hash):

        block = {

            'index': len(self.chain) + 1,
            'timestamp': str(time()),
            'file_hash': file_hash,
            'previous_hash': previous_hash

        }

        block['hash'] = self.hash(block)

        self.chain.append(block)

        return block


    # Generate Block Hash
    def hash(self, block):

        encoded_block = json.dumps(
            block,
            sort_keys=True
        ).encode()

        return hashlib.sha256(encoded_block).hexdigest()