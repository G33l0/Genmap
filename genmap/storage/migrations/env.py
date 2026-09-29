"""Alembic environment. Genmap runs migrations in process and passes the
connection through ``config.attributes``; the URL branch only serves
developers generating new revisions from the command line."""

from alembic import context
from sqlalchemy import create_engine

from genmap.storage.models import Base

config = context.config
target_metadata = Base.metadata


def run() -> None:
    connection = config.attributes.get("connection")
    if connection is not None:
        context.configure(connection=connection, target_metadata=target_metadata, render_as_batch=True)
        with context.begin_transaction():
            context.run_migrations()
        return
    engine = create_engine(config.get_main_option("sqlalchemy.url"))
    with engine.connect() as fresh:
        context.configure(connection=fresh, target_metadata=target_metadata, render_as_batch=True)
        with context.begin_transaction():
            context.run_migrations()


run()
