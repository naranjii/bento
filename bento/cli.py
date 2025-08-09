import click
from .main import process_input

@click.command()
@click.argument('input_value')
def main(input_value):
    """Query VirusTotal for a URL or file path."""
    process_input(input_value)
