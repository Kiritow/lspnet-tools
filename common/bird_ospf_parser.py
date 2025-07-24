import re
from dataclasses import dataclass
from common.utils import sudo_call_output


def get_blevel(s: str):
    match = re.match(r'^(\t*)', s)
    return len(match.group(1)) if match else 0

@dataclass
class _RouterInfo:
    router_id: str
    metric: int

@dataclass
class _NetworkInfo:
    network: str
    metric: int

@dataclass
class _ExternalNetworkInfo:
    network: str
    metric: int
    metric_type: int # 1 or 2
    via: str | None
    tag: int | None

@dataclass
class RouterInfo:
    # OSPFv2
    router_id: str
    distance: int
    vlinks: list[_RouterInfo] # virtual links
    routers: list[_RouterInfo]
    stubnets: list[_NetworkInfo]
    xnetworks: list[_NetworkInfo] # summarized networks
    xrouters: list[_RouterInfo] # summarized routers
    externals: list[_ExternalNetworkInfo]
    nssa_externals: list[_ExternalNetworkInfo]


class PeekableLines:
    def __init__(self, lines: list[str]):
        self.lines = lines
        self.index = 0

    def pop(self):
        if self.index < len(self.lines):
            line = self.lines[self.index]
            sline = line.strip()
            blevel = get_blevel(line)
            self.index += 1

            return line, sline, blevel
        return None
    
    def peek(self):
        if self.index < len(self.lines):
            line = self.lines[self.index]
            sline = line.strip()
            blevel = get_blevel(line)

            return line, sline, blevel
        return None



class OSPFStateParser:
    area_routers: dict[str, list[RouterInfo]]
    other_asbrs: list[RouterInfo]

    def __init__(self):
        self.area_routers = {}
        self.other_asbrs = []

    def parse_router(self, feeder: PeekableLines):
        router_info = RouterInfo(
            router_id="",
            distance=0,
            vlinks=[],
            routers=[],
            stubnets=[],
            xnetworks=[],
            xrouters=[],
            externals=[],
            nssa_externals=[]
        )
        while True:
            lpack = feeder.peek()
            if not lpack:
                break

            line, sline, blevel = lpack
            if not sline:
                feeder.pop()
                continue

            if blevel < 2:
                break

            feeder.pop()
            assert blevel == 2, "Invalid line level({}): {}".format(blevel, line)

            if sline.startswith("distance "):
                router_info.distance = int(sline.split()[1])
            elif sline.startswith("vlink "):
                parts = sline.split()
                assert len(parts) == 4 and parts[2] == "metric", "Invalid vlink format: {}".format(sline)
                router_info.vlinks.append(
                    _RouterInfo(
                        router_id=parts[1],
                        metric=int(parts[3])
                    )
                )
            elif sline.startswith("router "):
                parts = sline.split()
                assert len(parts) == 4 and parts[2] == "metric", "Invalid router format: {}".format(sline)
                router_info.routers.append(
                    _RouterInfo(
                        router_id=parts[1],
                        metric=int(parts[3])
                    )
                )
            elif sline.startswith("stubnet "):
                parts = sline.split()
                assert len(parts) == 4 and parts[2] == "metric", "Invalid stubnet format: {}".format(sline)
                router_info.stubnets.append(
                    _NetworkInfo(
                        network=parts[1],
                        metric=int(parts[3])
                    )
                )
            elif sline.startswith("xnetwork "):
                parts = sline.split()
                assert len(parts) == 4 and parts[2] == "metric", "Invalid xnetwork format: {}".format(sline)
                router_info.xnetworks.append(
                    _NetworkInfo(
                        network=parts[1],
                        metric=int(parts[3])
                    )
                )
            elif sline.startswith("xrouter "):
                parts = sline.split()
                assert len(parts) == 4 and parts[2] == "metric", "Invalid xrouter format: {}".format(sline)
                router_info.xrouters.append(
                    _RouterInfo(
                        router_id=parts[1],
                        metric=int(parts[3])
                    )
                )
            elif sline.startswith("external ") or sline.startswith("nssa_ext "):
                parts = sline.split()
                metric_type = 2 if "metric2" in parts else 1
                via = parts[parts.index("via") + 1] if "via" in parts else None
                tag = int(parts[parts.index("tag") + 1]) if "tag" in parts else None

                network_info  =_ExternalNetworkInfo(
                    network=parts[1],
                    metric_type=metric_type,
                    metric=int(parts[3]),
                    via=via,
                    tag=tag
                )

                if parts[0] == "external":
                    router_info.externals.append(network_info)
                else:
                    router_info.nssa_externals.append(network_info)
            else:
                print("unknown line in router info: {}".format(line))

        return router_info
    
    def parse_area(self, feeder: PeekableLines):
        routers: list[RouterInfo] = []

        while True:
            lpack = feeder.peek()
            if not lpack:
                break

            line, sline, blevel = lpack
            if not sline:
                feeder.pop()
                continue

            if blevel < 1:
                break

            feeder.pop()  # consume the line

            assert blevel == 1, "Invalid line level({}): {}".format(blevel, line)

            if sline.startswith("router "):
                router_id = sline.split()[1]
                router_detail = self.parse_router(feeder)
                router_detail.router_id = router_id
                routers.append(router_detail)
                continue
            else:
                print("unknown line in area: {}".format(line))

        return routers

    def parse(self, content: str):
        output = content.splitlines()
        feeder = PeekableLines(output)

        while True:
            lpack = feeder.pop()
            if not lpack:
                break

            line, sline, blevel = lpack
            if not sline:
                continue

            assert blevel == 0, "Invalid line level({}): {}".format(blevel, line)
            if sline.startswith("area "):
                current_area = sline.split()[1]
                area_routers = self.parse_area(feeder)
                self.area_routers[current_area] = area_routers
            elif sline.startswith("other ASBRs"):
                # Handle other ASBRs if needed
                area_routers = self.parse_area(feeder)
                self.other_asbrs.extend(area_routers)
            else:
                print("unknown line: {}".format(line))


def get_router_ospf_state(container_id: str):
    output = sudo_call_output(["podman", "exec", "-it", container_id, "birdc", "show", "ospf", "state", "all"])
    parser = OSPFStateParser()
    parser.parse(output)
    return parser.area_routers, parser.other_asbrs
