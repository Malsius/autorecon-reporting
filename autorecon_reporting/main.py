import base64
import os
import re
import sys

from jinja2 import Environment, PackageLoader
from libnmap.parser import NmapParser


def strip_ansi(string):
    pattern = re.compile(r'\x1B\[\d+(;\d+){0,2}m')
    stripped = pattern.sub('', string)
    return stripped


def parse_banner(banner):
    result = ""
    split_banner = banner.split("extrainfo:")
    try:
        extrainfo = split_banner[1].split("ostype:")[0].strip(" ()")
        result = f"({extrainfo})"
    except IndexError:
        pass
    split_banner = split_banner[0].split("version:")
    try:
        version = split_banner[1].split("ostype:")[0].strip()
        result = f"{version} {result}"
    except IndexError:
        pass
    split_banner = split_banner[0].split("product:")
    try:
        product = split_banner[1].split("ostype:")[0].strip()
        result = f"{product} {result}"
    except IndexError:
        pass
    return result.strip()


def render_report(data):
    reports_path = os.path.abspath(sys.argv[2])
    for host, protocols in data.items():
        context = {
            "host": host,
            "protocols": protocols
        }
        env = Environment(
            loader=PackageLoader("autorecon_reporting", "templates/"),
            trim_blocks=True,
            lstrip_blocks=True
        )
        template = env.get_template("template.jinja")
        output = template.render(context)
        report_html = os.path.join(reports_path, f"{host}.html")
        with open(report_html, "w") as file:
            file.write(output)


def parse_tools(service_path, protocol, port):
    result = {}
    for file in os.listdir(service_path):
        file_path = os.path.join(service_path, file)
        if os.path.isfile(file_path) and "_nmap" not in file:
            file_name, file_ext = os.path.splitext(file)
            if f"{protocol}_{port}_" in file_name:
                tool = file_name.split("_")[-1]
            else:
                tool = file_name
            if tool == "dirbuster":
                tool = "feroxbuster"
            if file_ext == ".png":
                with open(file_path, "rb") as img:
                    img_b64 = base64.b64encode(img.read()).decode('utf-8')
                    result[tool] = f"data:image/png;base64,{img_b64}"
            else:
                with open(file_path, "r") as tool_output:
                    result[tool] = strip_ansi(tool_output.read())
    return result


def parse_nmap_scripts(host_scripts_results, service_scripts_results, nmap_scripts=None):
    if not nmap_scripts:
        nmap_scripts = {}
    for script_result in host_scripts_results:
        nmap_scripts[script_result["id"]] = script_result["output"]
    for script_result in service_scripts_results:
        nmap_scripts[script_result["id"]] = script_result["output"]
    return nmap_scripts


def parse_service(service, host):
    return {
        "service": service.service,
        "banner": parse_banner(service.banner),
        "nmap_scripts": parse_nmap_scripts(host, service)
    }


def parse_protocol(host, host_address, protocol, result, host_scans_path):
    if host.is_up():
        if not result.get(host_address):
            result[host_address] = {}
        result[host_address][protocol] = {}
        for service in host.services:
            if service.open():
                result[host_address][protocol][service.port] = {
                    "service": service.service,
                    "banner": parse_banner(service.banner),
                    "nmap_scripts": parse_nmap_scripts(host.scripts_results, service.scripts_results),
                }
        for port, content in result[host_address][protocol].items():
            service_path = os.path.join(host_scans_path, f"{protocol}{port}")
            service_xml_path = os.path.join(service_path, "xml")
            if os.path.exists(service_xml_path):
                for file in os.listdir(service_xml_path):
                    service_xml_report = NmapParser.parse_fromfile(os.path.join(service_xml_path, file))
                    host = service_xml_report.hosts[0]
                    for host_service in host.services:
                        content["nmap_scripts"] = parse_nmap_scripts(host.scripts_results,
                                                                     host_service.scripts_results,
                                                                     content["nmap_scripts"])
            content["tools"] = parse_tools(service_path, protocol, port)
    return result


def main():
    result = {}
    source_path = os.path.abspath(sys.argv[1])
    host_list = [host for host in os.listdir(source_path) if host != "report.md"]
    for host_address in host_list:
        host_scans_path = os.path.join(source_path, host_address, "scans")

        if os.path.exists(os.path.join(host_scans_path, "xml", "_full_tcp_nmap.xml")):
            tcp_scan_report = NmapParser.parse_fromfile(os.path.join(host_scans_path, "xml", "_full_tcp_nmap.xml"))
        elif os.path.exists(os.path.join(host_scans_path, "xml", "_quick_tcp_nmap.xml")):
            tcp_scan_report = NmapParser.parse_fromfile(os.path.join(host_scans_path, "xml", "_quick_tcp_nmap.xml"))
        else:
            tcp_scan_report = None

        if tcp_scan_report:
            tcp_host = tcp_scan_report.hosts[0]
            result = parse_protocol(tcp_host, host_address, "tcp", result, host_scans_path)

        if os.path.exists(os.path.join(host_scans_path, "xml", "_top_100_udp_nmap.xml")):
            udp_scan_report = NmapParser.parse_fromfile(os.path.join(host_scans_path, "xml", "_top_100_udp_nmap.xml"))
        else:
            udp_scan_report = None

        if udp_scan_report:
            udp_host = udp_scan_report.hosts[0]
            result = parse_protocol(udp_host, host_address, "udp", result, host_scans_path)

    render_report(result)


if __name__ == '__main__':
    main()
