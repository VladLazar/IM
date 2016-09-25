"""empty message

Revision ID: 893eeb10481e
Revises: None
Create Date: 2016-09-11 14:26:59.137755

"""

# revision identifiers, used by Alembic.
revision = '893eeb10481e'
down_revision = None

from alembic import op
import sqlalchemy as sa


def upgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.create_table('conversation',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('is_conference', sa.Boolean(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('user',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('username', sa.String(length=100), nullable=True),
    sa.Column('password', sa.String(length=100), nullable=True),
    sa.Column('email', sa.String(length=100), nullable=True),
    sa.Column('authenticated', sa.Boolean(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_user_email'), 'user', ['email'], unique=True)
    op.create_index(op.f('ix_user_username'), 'user', ['username'], unique=True)
    op.create_table('invite',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('initiator', sa.String(), nullable=True),
    sa.Column('conference_id', sa.Integer(), nullable=True),
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('message',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('message', sa.String(), nullable=True),
    sa.Column('timestamp', sa.String(), nullable=True),
    sa.Column('sender', sa.String(), nullable=True),
    sa.Column('conversation_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['conversation_id'], ['conversation.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('relationship_table',
    sa.Column('conversation_id', sa.Integer(), nullable=True),
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['conversation_id'], ['user.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['conversation.id'], )
    )
    ### end Alembic commands ###


def downgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('relationship_table')
    op.drop_table('message')
    op.drop_table('invite')
    op.drop_index(op.f('ix_user_username'), table_name='user')
    op.drop_index(op.f('ix_user_email'), table_name='user')
    op.drop_table('user')
    op.drop_table('conversation')
    ### end Alembic commands ###
