package repo

import (
	"iptables-web/backend/internal/db"
	"iptables-web/backend/internal/models"

	"gorm.io/gorm"
)

type HostRepo struct{ db *gorm.DB }

func NewHostRepo() *HostRepo { return &HostRepo{db: db.DB()} }

func (r *HostRepo) Create(h *models.Host) error { return r.db.Create(h).Error }
func (r *HostRepo) Update(h *models.Host) error {
	return r.db.Model(&models.Host{}).Where("id = ?", h.ID).Updates(h).Error
}
func (r *HostRepo) Delete(id uint) error { return r.db.Delete(&models.Host{}, id).Error }
func (r *HostRepo) BatchDelete(ids []uint) (int64, error) {
	tx := r.db.Delete(&models.Host{}, ids)
	return tx.RowsAffected, tx.Error
}
func (r *HostRepo) List() ([]models.Host, error) {
	var hs []models.Host
	return hs, r.db.Order("id asc").Find(&hs).Error
}
func (r *HostRepo) Get(id uint) (*models.Host, error) {
	var h models.Host
	if err := r.db.First(&h, id).Error; err != nil {
		return nil, err
	}
	return &h, nil
}
func (r *HostRepo) FindByName(name string) (*models.Host, error) {
	var h models.Host
	if err := r.db.Where("name = ?", name).First(&h).Error; err != nil {
		return nil, err
	}
	return &h, nil
}
func (r *HostRepo) FindByIPPort(ip string, port int) (*models.Host, error) {
	var h models.Host
	if err := r.db.Where("ip = ? AND port = ?", ip, port).First(&h).Error; err != nil {
		return nil, err
	}
	return &h, nil
}
