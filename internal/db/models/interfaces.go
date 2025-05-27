package models

// UserService defines the interface for user operations
type UserService interface {
	Create(user *User) error
	GetByID(id uint) (*User, error)
	GetByUsername(username string) (*User, error)
	GetByEmail(email string) (*User, error)
	Update(user *User) error
	Delete(id uint) error
	List(limit, offset int) ([]*User, error)
}

// RepositoryService defines the interface for repository operations
type RepositoryService interface {
	Create(repo *Repository) error
	GetByID(id uint) (*Repository, error)
	GetByUsername(username, repoName string) (*Repository, error)
	Update(repo *Repository) error
	Delete(id uint) error
	ListByOwner(ownerID uint, limit, offset int) ([]*Repository, error)
}

// PermissionService defines the interface for permission operations
type PermissionService interface {
	Create(perm *Permission) error
	GetByUserAndRepo(userID, repoID uint) (*Permission, error)
	Update(perm *Permission) error
	DeleteByUserAndRepo(userID, repoID uint) error
	ListByRepository(repoID uint) ([]*Permission, error)
	HasPermission(userID, repoID uint, level string) (bool, error)
}

// CommitService defines the interface for commit operations
type CommitService interface {
	CreateCommit(commit *Commit) error
	GetCommitByHash(repoID uint, commitID string) (*Commit, error)
	GetCommitsByRepoID(repoID uint) ([]*Commit, error)
	AddCommitParent(commit *Commit, parent *Commit) error
	GetCommitParents(commitID string) ([]*Commit, error)
	GetCommitChildren(commitID string) ([]*Commit, error)
}

// BranchService defines the interface for branch operations
type BranchService interface {
	Create(branch *Branch) error
	GetByName(repoID uint, name string) (*Branch, error)
	GetDefaultBranch(repoID uint) (*Branch, error)
	ListByRepository(repoID uint) ([]*Branch, error)
	Update(branch *Branch) error
	Delete(repoID uint, name string) error
}
