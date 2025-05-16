from string import Template
from .report_config import TEMPLATES_DIR_PATH, DIR_REPORT_PATH
from .latex_utils import latex_table, latex_escape, write_latex, format_details
import os


class ReportManager:
    """Generates both reports."""

    def __init__(self, summary_data, db):
        """Setup for the report handling."""
        self.data = summary_data
        self.summary_id = self.data['id']
        self.db = db
        self.supervisor_template = self._load_template("supervisor.tex")
        self.admin_template = self._load_template("admin.tex")

    def _load_template(self, template) -> Template:
        """Load a LaTeX template file as a string.Template."""
        path = os.path.join(TEMPLATES_DIR_PATH, template)
        if not os.path.exists(path):
            raise FileNotFoundError(f"Template not found: {path}")
        with open(path, 'r', encoding='utf-8') as f:
            return Template(f.read())

    def render_supervisor(self, compile_pdf=False):
        """Render the supervisor report for this one country.

        Writes both .tex and optionally compiles to .pdf.
        """
        country = self.data['country']
        output_dir = os.path.join(DIR_REPORT_PATH, "supervisor")
        os.makedirs(output_dir, exist_ok=True)

        context = {
            'country': latex_escape(country),
            'scan_started': self.data['discovery_scan_start_ts'],
            'scan_finished': self.data['discovery_scan_done_ts'],
            'total_ips_scanned': self.data['total_ips_scanned'],
            'total_ports_scanned': self.data['total_ports_scanned'],
            'total_ports_open': self.data['total_ports_open'],
            'total_active_hosts': self.data['total_ips_active'],
            'ports_table': latex_table(self.data.get('open_ports_count') or {}, "Open Ports"),
            'services_table': latex_table(self.data.get('services_count') or {}, "Services"),
            'os_table': latex_table(self.data.get('os_count') or {}, "Operating Systems"),
            'versions_table': latex_table(self.data.get('versions_count') or {}, "Versions"),
            'products_table': latex_table(self.data.get('products_count') or {}, "Products"),
            'cpe_table': latex_table(self.data.get('cpe_count') or {}, "CPE"),
        }

        rendered = self.supervisor_template.substitute(context)
        tex_name = f"supervisor_summary_{self.summary_id}.tex"
        write_latex(rendered, tex_name, output_dir, compile_pdf)
        return os.path.join(output_dir, tex_name)

    def render_admin(self, compile_pdf=False):
        """Render the report for administrator for this one country."""
        country = self.data['country']
        cidrs = self.db.fetch_cidrs_for_nation()
        output_dir = os.path.join(DIR_REPORT_PATH, "admin")
        os.makedirs(output_dir, exist_ok=True)

        for cidr in cidrs:
            hosts = self.db.fetch_hosts_for_cidr(cidr)
            ports = self.db.fetch_ports_for_cidr(cidr)

            open_count = sum(len(ports.get(ip, [])) for ip in hosts)
            if open_count == 0:
                continue

            alive_ips = [ip for ip, r in hosts.items() if r['host_state'] == "alive"]
            starts = [hosts[ip]['scan_start_ts'] for ip in alive_ips]
            ends = [hosts[ip]['scan_done_ts'] for ip in alive_ips]

            context = {
                'country': latex_escape(country),
                'cidr': latex_escape(cidr),
                'whois': latex_escape(hosts[next(iter(hosts))]['org']),
                'start_time': min(starts) if starts else 'N/A',
                'end_time': max(ends) if ends else 'N/A',
                'open_ports': open_count,
                'active_ips': len(alive_ips),
                'total_ips': len(hosts),
                'details': format_details(list(hosts), ports),
            }

            rendered = self.admin_template.substitute(context)
            tex_name = f"supervisor_summary_{self.summary_id}.tex"
            write_latex(rendered, tex_name, output_dir, compile_pdf)
