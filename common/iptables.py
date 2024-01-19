import subprocess
import traceback

from .utils import sudo_wrap, sudo_call
from .utils import logger


def try_create_iptables_chain(table_name, chain_name):
    try:
        subprocess.run(sudo_wrap(["iptables", "-t", table_name, "-N", chain_name]), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, encoding='utf-8')
    except subprocess.CalledProcessError as e:
        if 'iptables: Chain already exists.' not in e.stderr:
            raise

        logger.info('iptables chain {} exists in {} table, skip creation.'.format(chain_name, table_name))


def try_append_iptables_rule(table_name, chain_name, rule_args):
    try:
        subprocess.run(sudo_wrap(["iptables", "-t", table_name, "-C", chain_name] + rule_args), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, encoding='utf-8')
    except subprocess.CalledProcessError as e:
        if 'iptables: Bad rule (does a matching rule exist in that chain?)' not in e.stderr and 'iptables: No chain/target/match by that name' not in e.stderr:
            raise

        logger.info('iptables rule not exist, adding: iptables -t {} -A {} {}'.format(table_name, chain_name, ' '.join(rule_args)))
        sudo_call(["iptables", "-t", table_name, "-A", chain_name] + rule_args)


def try_insert_iptables_rule(table_name, chain_name, rule_args):
    try:
        subprocess.run(sudo_wrap(["iptables", "-t", table_name, "-C", chain_name] + rule_args), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, encoding='utf-8')
    except subprocess.CalledProcessError as e:
        if 'iptables: Bad rule (does a matching rule exist in that chain?)' not in e.stderr and 'iptables: No chain/target/match by that name' not in e.stderr:
            raise

        logger.info('iptables rule not exist, inserting: iptables -t {} -I {} {}'.format(table_name, chain_name, rule_args))
        sudo_call(["iptables", "-t", table_name, "-I", chain_name] + rule_args)


def try_flush_iptables(table_name, chain_name):
    try:
        sudo_call(["iptables", "-t", table_name, "-F", chain_name])
    except Exception:
        logger.warning(traceback.format_exc())


def ensure_iptables(namespace):
    try_create_iptables_chain("nat", f"{namespace}-POSTROUTING")
    try_insert_iptables_rule("nat", "POSTROUTING", ["-j", "{}-POSTROUTING".format(namespace)])

    try_create_iptables_chain("nat", f"{namespace}-PREROUTING")
    try_insert_iptables_rule("nat", "PREROUTING", ["-j", "{}-PREROUTING".format(namespace)])

    try_create_iptables_chain("raw", f"{namespace}-PREROUTING")
    try_insert_iptables_rule("raw", "PREROUTING", ["-j", "{}-PREROUTING".format(namespace)])

    try_create_iptables_chain("mangle", f"{namespace}-POSTROUTING")
    try_insert_iptables_rule("mangle", "POSTROUTING", ["-j", "{}-POSTROUTING".format(namespace)])

    try_create_iptables_chain("filter", f"{namespace}-FORWARD")
    try_insert_iptables_rule("filter", "FORWARD", ["-j", "{}-FORWARD".format(namespace)])

    try_create_iptables_chain("filter", f"{namespace}-INPUT")
    try_insert_iptables_rule("filter", "INPUT", ["-j", "{}-INPUT".format(namespace)])


def clear_iptables(namespace):
    try_flush_iptables("nat", f"{namespace}-POSTROUTING")
    try_flush_iptables("nat", f"{namespace}-PREROUTING")
    try_flush_iptables("raw", f"{namespace}-PREROUTING")
    try_flush_iptables("mangle", f"{namespace}-POSTROUTING")
    try_flush_iptables("filter", f"{namespace}-FORWARD")
    try_flush_iptables("filter", f"{namespace}-INPUT")

    # in namespace
    try:
        sudo_call(["ip", "netns", "exec", namespace, "iptables", "-F", "FORWARD"])
    except Exception:
        logger.warning(traceback.format_exc())