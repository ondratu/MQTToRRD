Contribution
============

If you have any improvement or idea what this tool can do, please tell me that,
send me pull reqeuset, write issue. Thanks a lot!

Tests
-----
``test`` command in setup.py run unittest automatically, but you can run
unittest manually by next commands:

.. code:: sh

    # unittest (builtin)
    ~$ python3 -m unittest discover -v ./tests

    # pytest (extra module)
    ~$ pytest-3 -v

**pytest** package have many additional extensions so you can use that.
Next command check all .rst files, source code with pep8 and doctest checkers.

.. code:: sh

    # check pep8 and doctest with pytest (pytest + pep8 extension + doctest-plus)
    ~$ pytest -v --pep8 --doctest-rst
