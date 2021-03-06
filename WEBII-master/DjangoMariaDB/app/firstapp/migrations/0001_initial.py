# Generated by Django 3.0.4 on 2020-03-19 01:53

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Estados',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('clave', models.CharField(max_length=2)),
                ('name', models.CharField(max_length=45)),
                ('abrev', models.CharField(max_length=16)),
                ('abrev_pm', models.CharField(max_length=16)),
                ('id_country', models.IntegerField(blank=True, null=True)),
                ('risk', models.DecimalField(blank=True, decimal_places=2, max_digits=5, null=True)),
            ],
            options={
                'db_table': 'estados',
                'managed': False,
            },
        ),
    ]
