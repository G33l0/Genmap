"""Initial schema

Revision ID: 0001
Revises:
Create Date: 2026-09-29 06:01:07.403128
"""

from alembic import op
import sqlalchemy as sa


revision = '0001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('profile',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=120), nullable=False),
    sa.Column('description', sa.Text(), nullable=False),
    sa.Column('configuration', sa.JSON(), nullable=False),
    sa.Column('builtin_key', sa.String(length=64), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_profile')),
    sa.UniqueConstraint('builtin_key', name=op.f('uq_profile_builtin_key')),
    sa.UniqueConstraint('name', name=op.f('uq_profile_name'))
    )
    op.create_table('tag',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=60), nullable=False),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_tag')),
    sa.UniqueConstraint('name', name=op.f('uq_tag_name'))
    )
    op.create_table('target_group',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=120), nullable=False),
    sa.Column('description', sa.Text(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_target_group')),
    sa.UniqueConstraint('name', name=op.f('uq_target_group_name'))
    )
    op.create_table('scan',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('run_id', sa.String(length=64), nullable=False),
    sa.Column('module_id', sa.String(length=64), nullable=False),
    sa.Column('profile_id', sa.Integer(), nullable=True),
    sa.Column('profile_name', sa.String(length=120), nullable=True),
    sa.Column('target_summary', sa.String(length=300), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('started_at', sa.DateTime(), nullable=True),
    sa.Column('finished_at', sa.DateTime(), nullable=True),
    sa.Column('status', sa.String(length=32), nullable=False),
    sa.Column('exit_code', sa.Integer(), nullable=True),
    sa.Column('nmap_version', sa.String(length=40), nullable=True),
    sa.Column('command_display', sa.Text(), nullable=True),
    sa.Column('command_arguments', sa.JSON(), nullable=True),
    sa.Column('configuration', sa.JSON(), nullable=False),
    sa.Column('error_message', sa.Text(), nullable=True),
    sa.Column('error_remedy', sa.Text(), nullable=True),
    sa.Column('warnings', sa.JSON(), nullable=False),
    sa.Column('hosts_total', sa.Integer(), nullable=False),
    sa.Column('hosts_up', sa.Integer(), nullable=False),
    sa.Column('open_ports', sa.Integer(), nullable=False),
    sa.Column('services', sa.Integer(), nullable=False),
    sa.Column('truncated', sa.Boolean(), nullable=False),
    sa.Column('results_indexed', sa.Boolean(), nullable=False),
    sa.Column('folder_missing', sa.Boolean(), nullable=False),
    sa.ForeignKeyConstraint(['profile_id'], ['profile.id'], name=op.f('fk_scan_profile_id_profile'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_scan')),
    sa.UniqueConstraint('run_id', name=op.f('uq_scan_run_id'))
    )
    with op.batch_alter_table('scan', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_scan_created_at'), ['created_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_scan_module_id'), ['module_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_scan_status'), ['status'], unique=False)

    op.create_table('target_group_entry',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('group_id', sa.Integer(), nullable=False),
    sa.Column('expression', sa.String(length=300), nullable=False),
    sa.Column('excluded', sa.Boolean(), nullable=False),
    sa.Column('position', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['group_id'], ['target_group.id'], name=op.f('fk_target_group_entry_group_id_target_group'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_target_group_entry'))
    )
    with op.batch_alter_table('target_group_entry', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_target_group_entry_group_id'), ['group_id'], unique=False)

    op.create_table('host',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('scan_id', sa.Integer(), nullable=False),
    sa.Column('state', sa.String(length=20), nullable=False),
    sa.Column('reason', sa.String(length=60), nullable=True),
    sa.Column('primary_address', sa.String(length=64), nullable=True),
    sa.Column('primary_hostname', sa.String(length=255), nullable=True),
    sa.Column('mac_address', sa.String(length=32), nullable=True),
    sa.Column('mac_vendor', sa.String(length=120), nullable=True),
    sa.Column('distance', sa.Integer(), nullable=True),
    sa.Column('uptime_seconds', sa.Integer(), nullable=True),
    sa.Column('last_boot', sa.String(length=60), nullable=True),
    sa.Column('os_name', sa.String(length=255), nullable=True),
    sa.Column('os_accuracy', sa.Integer(), nullable=True),
    sa.Column('started_at', sa.DateTime(), nullable=True),
    sa.Column('ended_at', sa.DateTime(), nullable=True),
    sa.Column('extra', sa.JSON(), nullable=False),
    sa.ForeignKeyConstraint(['scan_id'], ['scan.id'], name=op.f('fk_host_scan_id_scan'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_host'))
    )
    with op.batch_alter_table('host', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_host_os_name'), ['os_name'], unique=False)
        batch_op.create_index(batch_op.f('ix_host_primary_address'), ['primary_address'], unique=False)
        batch_op.create_index(batch_op.f('ix_host_primary_hostname'), ['primary_hostname'], unique=False)
        batch_op.create_index(batch_op.f('ix_host_scan_id'), ['scan_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_host_state'), ['state'], unique=False)

    op.create_table('report',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('scan_id', sa.Integer(), nullable=True),
    sa.Column('run_id', sa.String(length=64), nullable=True),
    sa.Column('title', sa.String(length=300), nullable=False),
    sa.Column('format', sa.String(length=10), nullable=False),
    sa.Column('path', sa.Text(), nullable=False),
    sa.Column('options', sa.JSON(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['scan_id'], ['scan.id'], name=op.f('fk_report_scan_id_scan'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_report'))
    )
    with op.batch_alter_table('report', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_report_scan_id'), ['scan_id'], unique=False)

    op.create_table('scan_tag',
    sa.Column('scan_id', sa.Integer(), nullable=False),
    sa.Column('tag_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['scan_id'], ['scan.id'], name=op.f('fk_scan_tag_scan_id_scan'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['tag_id'], ['tag.id'], name=op.f('fk_scan_tag_tag_id_tag'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('scan_id', 'tag_id', name=op.f('pk_scan_tag'))
    )
    op.create_table('scan_target',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('scan_id', sa.Integer(), nullable=False),
    sa.Column('expression', sa.String(length=300), nullable=False),
    sa.Column('excluded', sa.Boolean(), nullable=False),
    sa.ForeignKeyConstraint(['scan_id'], ['scan.id'], name=op.f('fk_scan_target_scan_id_scan'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_scan_target'))
    )
    with op.batch_alter_table('scan_target', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_scan_target_expression'), ['expression'], unique=False)
        batch_op.create_index(batch_op.f('ix_scan_target_scan_id'), ['scan_id'], unique=False)

    op.create_table('address',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('host_id', sa.Integer(), nullable=False),
    sa.Column('address', sa.String(length=64), nullable=False),
    sa.Column('address_type', sa.String(length=10), nullable=False),
    sa.Column('vendor', sa.String(length=120), nullable=True),
    sa.ForeignKeyConstraint(['host_id'], ['host.id'], name=op.f('fk_address_host_id_host'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_address'))
    )
    with op.batch_alter_table('address', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_address_address'), ['address'], unique=False)
        batch_op.create_index(batch_op.f('ix_address_host_id'), ['host_id'], unique=False)

    op.create_table('hostname',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('host_id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=255), nullable=False),
    sa.Column('hostname_type', sa.String(length=20), nullable=True),
    sa.ForeignKeyConstraint(['host_id'], ['host.id'], name=op.f('fk_hostname_host_id_host'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_hostname'))
    )
    with op.batch_alter_table('hostname', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_hostname_host_id'), ['host_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_hostname_name'), ['name'], unique=False)

    op.create_table('os_match',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('host_id', sa.Integer(), nullable=False),
    sa.Column('rank', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=255), nullable=False),
    sa.Column('accuracy', sa.Integer(), nullable=True),
    sa.Column('line', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['host_id'], ['host.id'], name=op.f('fk_os_match_host_id_host'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_os_match'))
    )
    with op.batch_alter_table('os_match', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_os_match_host_id'), ['host_id'], unique=False)

    op.create_table('port',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('host_id', sa.Integer(), nullable=False),
    sa.Column('protocol', sa.String(length=8), nullable=False),
    sa.Column('number', sa.Integer(), nullable=False),
    sa.Column('state', sa.String(length=24), nullable=False),
    sa.Column('reason', sa.String(length=60), nullable=True),
    sa.Column('reason_ttl', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['host_id'], ['host.id'], name=op.f('fk_port_host_id_host'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_port')),
    sa.UniqueConstraint('host_id', 'protocol', 'number', name='uq_port_host_protocol_number')
    )
    with op.batch_alter_table('port', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_port_host_id'), ['host_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_port_number'), ['number'], unique=False)
        batch_op.create_index(batch_op.f('ix_port_state'), ['state'], unique=False)

    op.create_table('traceroute_hop',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('host_id', sa.Integer(), nullable=False),
    sa.Column('ttl', sa.Integer(), nullable=False),
    sa.Column('address', sa.String(length=64), nullable=True),
    sa.Column('rtt', sa.Float(), nullable=True),
    sa.Column('hostname', sa.String(length=255), nullable=True),
    sa.ForeignKeyConstraint(['host_id'], ['host.id'], name=op.f('fk_traceroute_hop_host_id_host'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_traceroute_hop'))
    )
    with op.batch_alter_table('traceroute_hop', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_traceroute_hop_address'), ['address'], unique=False)
        batch_op.create_index(batch_op.f('ix_traceroute_hop_host_id'), ['host_id'], unique=False)

    op.create_table('cpe',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('host_id', sa.Integer(), nullable=False),
    sa.Column('port_id', sa.Integer(), nullable=True),
    sa.Column('source', sa.String(length=10), nullable=False),
    sa.Column('value', sa.String(length=255), nullable=False),
    sa.ForeignKeyConstraint(['host_id'], ['host.id'], name=op.f('fk_cpe_host_id_host'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['port_id'], ['port.id'], name=op.f('fk_cpe_port_id_port'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_cpe'))
    )
    with op.batch_alter_table('cpe', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_cpe_host_id'), ['host_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_cpe_value'), ['value'], unique=False)

    op.create_table('os_class',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('os_match_id', sa.Integer(), nullable=False),
    sa.Column('os_type', sa.String(length=80), nullable=True),
    sa.Column('vendor', sa.String(length=120), nullable=True),
    sa.Column('family', sa.String(length=120), nullable=True),
    sa.Column('generation', sa.String(length=60), nullable=True),
    sa.Column('accuracy', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['os_match_id'], ['os_match.id'], name=op.f('fk_os_class_os_match_id_os_match'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_os_class'))
    )
    with op.batch_alter_table('os_class', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_os_class_os_match_id'), ['os_match_id'], unique=False)

    op.create_table('script_result',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('scan_id', sa.Integer(), nullable=False),
    sa.Column('host_id', sa.Integer(), nullable=True),
    sa.Column('port_id', sa.Integer(), nullable=True),
    sa.Column('phase', sa.String(length=8), nullable=False),
    sa.Column('script_id', sa.String(length=120), nullable=False),
    sa.Column('output', sa.Text(), nullable=False),
    sa.Column('structured', sa.JSON(), nullable=True),
    sa.ForeignKeyConstraint(['host_id'], ['host.id'], name=op.f('fk_script_result_host_id_host'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['port_id'], ['port.id'], name=op.f('fk_script_result_port_id_port'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['scan_id'], ['scan.id'], name=op.f('fk_script_result_scan_id_scan'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_script_result'))
    )
    with op.batch_alter_table('script_result', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_script_result_host_id'), ['host_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_script_result_port_id'), ['port_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_script_result_scan_id'), ['scan_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_script_result_script_id'), ['script_id'], unique=False)

    op.create_table('service',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('port_id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=80), nullable=True),
    sa.Column('product', sa.String(length=200), nullable=True),
    sa.Column('version', sa.String(length=120), nullable=True),
    sa.Column('extra_info', sa.String(length=255), nullable=True),
    sa.Column('method', sa.String(length=16), nullable=True),
    sa.Column('confidence', sa.Integer(), nullable=True),
    sa.Column('tunnel', sa.String(length=16), nullable=True),
    sa.Column('os_type', sa.String(length=80), nullable=True),
    sa.Column('device_type', sa.String(length=80), nullable=True),
    sa.Column('hostname', sa.String(length=255), nullable=True),
    sa.Column('fingerprint', sa.Text(), nullable=True),
    sa.Column('extra', sa.JSON(), nullable=False),
    sa.ForeignKeyConstraint(['port_id'], ['port.id'], name=op.f('fk_service_port_id_port'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_service')),
    sa.UniqueConstraint('port_id', name=op.f('uq_service_port_id'))
    )
    with op.batch_alter_table('service', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_service_name'), ['name'], unique=False)
        batch_op.create_index(batch_op.f('ix_service_product'), ['product'], unique=False)



def downgrade() -> None:
    with op.batch_alter_table('service', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_service_product'))
        batch_op.drop_index(batch_op.f('ix_service_name'))

    op.drop_table('service')
    with op.batch_alter_table('script_result', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_script_result_script_id'))
        batch_op.drop_index(batch_op.f('ix_script_result_scan_id'))
        batch_op.drop_index(batch_op.f('ix_script_result_port_id'))
        batch_op.drop_index(batch_op.f('ix_script_result_host_id'))

    op.drop_table('script_result')
    with op.batch_alter_table('os_class', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_os_class_os_match_id'))

    op.drop_table('os_class')
    with op.batch_alter_table('cpe', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_cpe_value'))
        batch_op.drop_index(batch_op.f('ix_cpe_host_id'))

    op.drop_table('cpe')
    with op.batch_alter_table('traceroute_hop', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_traceroute_hop_host_id'))
        batch_op.drop_index(batch_op.f('ix_traceroute_hop_address'))

    op.drop_table('traceroute_hop')
    with op.batch_alter_table('port', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_port_state'))
        batch_op.drop_index(batch_op.f('ix_port_number'))
        batch_op.drop_index(batch_op.f('ix_port_host_id'))

    op.drop_table('port')
    with op.batch_alter_table('os_match', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_os_match_host_id'))

    op.drop_table('os_match')
    with op.batch_alter_table('hostname', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_hostname_name'))
        batch_op.drop_index(batch_op.f('ix_hostname_host_id'))

    op.drop_table('hostname')
    with op.batch_alter_table('address', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_address_host_id'))
        batch_op.drop_index(batch_op.f('ix_address_address'))

    op.drop_table('address')
    with op.batch_alter_table('scan_target', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_scan_target_scan_id'))
        batch_op.drop_index(batch_op.f('ix_scan_target_expression'))

    op.drop_table('scan_target')
    op.drop_table('scan_tag')
    with op.batch_alter_table('report', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_report_scan_id'))

    op.drop_table('report')
    with op.batch_alter_table('host', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_host_state'))
        batch_op.drop_index(batch_op.f('ix_host_scan_id'))
        batch_op.drop_index(batch_op.f('ix_host_primary_hostname'))
        batch_op.drop_index(batch_op.f('ix_host_primary_address'))
        batch_op.drop_index(batch_op.f('ix_host_os_name'))

    op.drop_table('host')
    with op.batch_alter_table('target_group_entry', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_target_group_entry_group_id'))

    op.drop_table('target_group_entry')
    with op.batch_alter_table('scan', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_scan_status'))
        batch_op.drop_index(batch_op.f('ix_scan_module_id'))
        batch_op.drop_index(batch_op.f('ix_scan_created_at'))

    op.drop_table('scan')
    op.drop_table('target_group')
    op.drop_table('tag')
    op.drop_table('profile')
