class FaultModel:
    """A fault model with its characteristics and behavior."""
    name = ""
    docs = ""
    nb_args = 0

    def __init__(self, config, args):
        super().__init__()
        self.config = config
        self.args = args

    def edited_memory_locations(self):
        """Returns the locations of the bits edited by the fault model."""

    def apply(self, opened_file):
        """Apply the fault model to the given file."""
