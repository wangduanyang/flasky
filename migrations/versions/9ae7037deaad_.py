"""empty message

Revision ID: 9ae7037deaad
Revises: d276be48fbab
Create Date: 2016-03-03 18:08:33.448743

"""

# revision identifiers, used by Alembic.
revision = '9ae7037deaad'
down_revision = 'd276be48fbab'

from alembic import op
import sqlalchemy as sa


def upgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.add_column('users', sa.Column('avatar_hash', sa.String(length=32), nullable=True))
    ### end Alembic commands ###


def downgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('users', 'avatar_hash')
    ### end Alembic commands ###
