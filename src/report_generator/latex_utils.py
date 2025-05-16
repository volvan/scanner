import re
import shutil
import ast
import os
import subprocess
from collections import defaultdict
from .report_config import TOP_ITEMS


def latex_escape(s) -> str:
    """Escape special characters for safe use in LaTeX documents."""
    s = str(s)
    escape_map = {
        '&': r'\&', '%': r'\%', '$': r'\$', '#': r'\#',
        '_': r'\_', '{': r'\{', '}': r'\}', '~': r'\textasciitilde{}',
        '^': r'\^{}', '\\': r'\textbackslash{}',
    }
    pattern = re.compile("|".join(re.escape(k) for k in escape_map))
    return pattern.sub(lambda m: escape_map[m.group()], s)


def latex_table(data, title: str) -> str:
    """Convert a dict or stringified dict into a LaTeX table of the top TOP_ITEMS entries.

    If parsing fails, returns an italic “failed” message.
    """
    if isinstance(data, dict):
        items = data
    else:
        try:
            items = ast.literal_eval(data)
        except Exception:
            return f"\\textit{{Failed to parse data for {latex_escape(title)}}}"

    # sort by count descending and take top N
    sorted_items = sorted(items.items(), key=lambda kv: kv[1], reverse=True)[:TOP_ITEMS]

    lines = [
        "\\begin{tabular}{@{}ll@{}}",
        "\\toprule",
        "Item & Count \\\\",
        "\\midrule"
    ]
    # build rows
    for key, count in sorted_items:
        lines.append(f"{latex_escape(key)} & {latex_escape(count)} \\\\")
    lines += [
        "\\bottomrule",
        "\\end{tabular}",
    ]
    return "\n".join(lines)


def write_latex(tex_str, filename, output_dir, compile_pdf):
    """ Write a LaTeX string to a file and optionally compile it to a PDF.

    Args:
        tex_str (str): The LaTeX source as a string.
        filename (str): The output `.tex` filename.
        output_dir (str): Directory to write the output files.
        compile_pdf (bool): Whether to compile the LaTeX file to PDF using pdflatex.

    Raises:
        subprocess.CalledProcessError: If pdflatex compilation fails.
    """
    os.makedirs(output_dir, exist_ok=True)
    tex_path = os.path.join(output_dir, filename)
    with open(tex_path, 'w', encoding='utf-8') as f:
        f.write(tex_str)
    print(f"Wrote {tex_path}")

    if not compile_pdf:
        return

    if shutil.which('pdflatex') is None:
        print("pdflatex not found; skipping PDF compilation.")
        return
    subprocess.run([
        'pdflatex',
        '-interaction=nonstopmode',
        f'-output-directory={output_dir}',
        tex_path
    ], check=True)
    pdf_name = filename.rsplit('.', 1)[0] + '.pdf'
    print(f"Compiled PDF: {os.path.join(output_dir, pdf_name)}")


def group_by_cidr(hosts: dict) -> dict:
    """Group IPs by their CIDR block.

    hosts: {ip: record}
    returns {cidr: [ip, …]}
    """
    cidr_map = defaultdict(list)
    for ip, rec in hosts.items():
        cidr_map[rec['cidr']].append(ip)
    return cidr_map


def format_details(ips: list, port_data: dict) -> str:
    """Format per-IP port details into a LaTeX Verbatim section."""
    sections = []
    for ip in sorted(ips):
        entries = port_data.get(ip, [])
        if not entries:
            continue

        header = f"\\textbf{{IP: {latex_escape(ip)} ({len(entries)} open/filtered ports)}}"
        lines = []
        for rec in sorted(entries, key=lambda r: int(r['port'])):
            state = rec['port_state'].strip()
            lines.append(
                f"  Port {latex_escape(rec['port'])} "
                f"({latex_escape(rec['port_protocol'])}): "
                f"{latex_escape(rec['port_service'])} "
                f"[{latex_escape(state)}]"
            )

        block = "\n".join(lines)
        sections.append(
            f"{header}\n"
            "\\begin{Verbatim}[breaklines=true, breakanywhere=true]\n"
            f"{block}\n"
            "\\end{Verbatim}\n"
        )
    return "\n\\vspace{1em}\n".join(sections)
