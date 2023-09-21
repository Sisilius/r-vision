import argparse

from google.protobuf.json_format import ParseDict, MessageToJson
from lxml import objectify

import oval_pb2 as Oval


class OvalParser:
    def _read_oval(self, path: str):
        self.oval_ns = "http://oval.mitre.org/XMLSchema/oval-definitions-5"
        self.tree = objectify.parse(path)
        self.root = self.tree.getroot()

    def _get_state(self, state_ref: str) -> dict:
        states = self.root.find(".//{%s}states" % self.oval_ns)
        state = next(
            el for el in states.iterchildren()
            if el.attrib["id"] == state_ref
        )
        formated_state = {}
        for child in state.iterchildren():
            tag_ = child.tag.split("}")[1]
            datatype = child.attrib.get("datatype")
            if datatype is not None:
                datatype = datatype.upper().replace(" ", "_")

            operation = child.attrib.get("operation")
            if operation is not None:
                operation = operation.upper().replace(" ", "_")

            value = child.text

            formated_state[tag_] = {k: v for k, v in {
                "datatype": datatype,
                "operation": operation,
                "value": value
            }.items() if v is not None}

        return formated_state

    def _get_object(self, object_ref: str) -> dict:
        objects = self.root.find(".//{%s}objects" % self.oval_ns)
        object_ = next(
            el for el in objects.iterchildren()
            if el.attrib["id"] == object_ref
        )
        formated_object = {}
        for child in object_.iterchildren():
            tag_ = child.tag.split("}")[1]
            if tag_ == "behaviors":
                formated_object[tag_] = {
                    k: v == 'true' for k, v in child.attrib.items()
                }
            else:
                datatype = child.attrib.get("datatype")
                if datatype is not None:
                    datatype = datatype.upper().replace(" ", "_")

                operation = child.attrib.get("operation")
                if operation is not None:
                    operation = operation.upper().replace(" ", "_")

                value = child.text

                formated_object[tag_] = {k: v for k, v in {
                    "datatype": datatype,
                    "operation": operation,
                    "value": value
                }.items() if v is not None}

        return formated_object

    def _get_test(self, test_ref) -> dict:
        tests = self.root.find(".//{%s}tests" % self.oval_ns)
        check_type, check, object_ref, state_ref = next(
            (
                i.tag.split("}")[1],
                i.attrib["check"].upper().replace(" ", "_"),
                i.object.attrib["object_ref"],
                i.state.attrib["state_ref"]
            ) for i in tests.iterchildren()
            if i.attrib["id"] == test_ref
        )

        return {
            "check_type": check_type,
            "check": check,
            "object": self._get_object(object_ref),
            "state": self._get_state(state_ref)
        }

    def _get_criteries(self, el) -> dict:
        if el.tag == '{%s}criteria' % self.oval_ns:
            data = {}
            data.update(el.attrib)
            for desc in el.iterchildren():
                key = "criterion" if "criterion" in desc.tag else "criteria"
                if key == "criterion":
                    if key not in data:
                        data[key] = {}
                    data[key] = self._get_criteries(desc)
                else:
                    data[key] = self._get_criteries(desc)
            return data
        else:
            return self._get_test(el.attrib["test_ref"])

    def _get_definitions(self, limit):
        return self.root.findall(".//{%s}definition" % self.oval_ns)[:limit]

    def parse(self, path: str, limit: int | None = None) -> list[dict]:
        self._read_oval(path=path)
        vulnerability_list = []
        definitions = self._get_definitions(limit=limit)
        for d in definitions:
            vulnerability = {}
            metadata = d.metadata
            vulnerability["id"] = d.attrib["id"]
            vulnerability["class_"] = d.attrib["class"].upper()
            vulnerability["title"] = metadata.title.text
            vulnerability["description"] = metadata.description.text
            vulnerability["family"] = metadata.affected.attrib["family"]
            vulnerability["cve"] = [
                {
                    "id": i.text,
                    "cvss3": i.attrib["cvss3"]
                }
                for i in metadata.advisory.cve
            ]
            vulnerability["criteria"] = self._get_criteries(d.criteria)
            vulnerability_list.append(vulnerability)

        return vulnerability_list


if __name__ == "__main__":
    oval = OvalParser()

    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--infile',
        type=str,
        help='Input oval file'
    )
    parser.add_argument(
        '--outfile',
        type=str,
        help='Output binary file',
        default=None
    )
    parser.add_argument(
        '--outstd',
        help='Output json in stdout',
        action='store_true',
        default=None
    )
    parser.add_argument(
        '--limit',
        type=int,
        help='Limit of definitions',
        default=None
    )
    args = parser.parse_args()

    vulnerability = oval.parse(args.infile, args.limit)
    message = ParseDict(
        {"vulnerability": vulnerability},
        Oval.VulnerabilityList()
    )

    if args.outfile:
        if not str(args.outfile).endswith(".bin"):
            filename = f"{args.outfile}.bin"
        else:
            filename = args.outfile

        with open(filename, "wb") as f:
            f.write(message.SerializeToString())

    if args.outstd:
        print(MessageToJson(message))
