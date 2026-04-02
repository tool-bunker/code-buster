from ruamel.yaml import YAML
yaml = YAML(typ="safe", pure=True)
safe_config = yaml.load(source)
yaml = YAML()
unsafe_config = yaml.load(source)
