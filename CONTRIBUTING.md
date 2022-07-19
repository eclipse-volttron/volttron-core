Contributor License
-------------------

VOLTTRON is an Eclipse Foundation project.  If this is your first time contributing to an Eclipse Foundation project, you'll need to sign the [Eclipse Contributor Agreement][ECA].

- [Create an account](https://dev.eclipse.org/site_login/createaccount.php) on dev.eclipse.org
- Open your [Account Settings tab](https://dev.eclipse.org/site_login/myaccount.php#open_tab_accountsettings), enter your GitHub ID and click Update Account
- Read and [sign the ECA](https://dev.eclipse.org/site_login/myaccount.php#open_tab_cla)
- Use the exact same email address for your Eclipse account and your commit author.

Issues
------

Search the [issue tracker](https://github.com/volttron/volttron-core/issues) for a relevant issue or create a new one.

Making changes
--------------

Fork the repository in GitHub and make changes in your fork.

Submit a pull request.

Contact us
----------

[Join the mailing list][mailing-list] or email volttron@pnnl.gov to discuss your ideas and get help.

Semantic Versioning
-------------------

VOLTTRON version numbers follow [Semantic Versioning][semver]. This means we increment the major version when we make incompatible API changes. This includes any changes which

- break source compatibility
- break serialization compatibility

Commit messages
---------------

- [Use the imperative mood][imperative-mood] as in "Fix bug" or "Add feature" rather than "Fixed bug" or "Added feature"
- [Mention the GitHub issue][github-issue] when relevant
- It's a good idea to follow the [advice in Pro Git](https://git-scm.com/book/ch5-2.html)

Pull requests
-------------

Excessive branching and merging can make git history confusing. With that in mind

- [Squash your commits down to a few commits][squash], or one commit, before submitting a pull request
- [Rebase your pull request changes on top of the current main][rebase]. Pull requests shouldn't include merge commits.

Submit your pull request when ready. Three checks will be kicked off automatically.

- IP Validation: Checks that all committers signed the Eclipse CLA and signed their commits.
- Continuous integration: [GitHub Actions][github] that run pytests and CodeQL.
- The standard GitHub check that the pull request has no conflicts with the base branch.

Make sure all the checks pass. One of the committers will take a look and provide feedback or merge your contribution.

That's it! Thanks for contributing to VOLTTRON!

[ECA]:             https://www.eclipse.org/legal/ECA.php
[semver]:          http://semver.org/
[squash]:          https://medium.com/@slamflipstrom/a-beginners-guide-to-squashing-commits-with-git-rebase-8185cf6e62ec
[rebase]:          https://github.com/edx/edx-platform/wiki/How-to-Rebase-a-Pull-Request
[github]:          https://github.com/volttron-core/volttron/actions/actions
[imperative-mood]: https://github.com/git/git/blob/master/Documentation/SubmittingPatches
[github-issue]:    https://help.github.com/articles/closing-issues-via-commit-messages/
