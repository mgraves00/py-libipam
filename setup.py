from setuptools import setup, find_packages

setup( name="libipam",
	version="1.0.9",
	author="Michael Graves",
	author_email="code@brainfat.net",
	packages=find_packages("src"),
    package_dir={"": "src"},
    url = "https://github.com/mgraves00/py-libipam",
	include_package_data=True,
	long_description=open('README.md').read(),
    keywords="ipam dns",
    install_requires = [
        "requests"
    ],
    classifiers=[
        "Environment :: Console",
        "License :: OSI Approved :: BSD License",
        "Programming Language :: Python :: 3",
        "Topic :: Internet :: Name Service (DNS)"
    ],
    package_data={
        "": ['*.schema']
    }
)

