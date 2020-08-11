#ifndef IRODS_SPECIAL_COLLECTION_PROXY_HPP
#define IRODS_SPECIAL_COLLECTION_PROXY_HPP

#include "objInfo.h"

namespace irods::experimental {

    template<
        typename T,
        typename = std::enable_if_t<
            std::is_same_v<specColl_t, typename std::remove_const_t<T>>
        >
    >
    class special_collection_proxy {
    public:
        using sc_type = T;
        using sc_pointer_type = sc_type*;
        using special_collection_class_type = specCollClass_t;
        using struct_file_type = structFileType_t;

        // ctor
        explicit special_collection_proxy(sc_type& _sc) : sc_{&_sc} {}

        // accessors
        auto special_collection_class() const noexcept -> special_collection_class_type { return sc_->collClass; }

        auto struct_file() const noexcept -> struct_file_type { return sc_->type; }

        auto collection() const noexcept -> std::string_view { return sc_->collection; }

        auto logical_path() const noexcept -> std::string_view { return sc_->objPath; }

        auto resource_name() const noexcept -> std::string_view { return sc_->resource; }

        auto resource_hierarchy() const noexcept -> std::string_view { return sc_->rescHier; }

        auto physical_path() const noexcept -> std::string_view { return sc_->phyPath; }

        auto cache_directory() const noexcept -> std::string_view { return sc_->cacheDir; }

        auto cache_is_dirty() const noexcept -> int { return sc_->cacheDirty; }

        auto replica_number() const noexcept -> int { return sc_->replNum; }

        auto get() const noexcept -> const sc_pointer_type { return sc_; }

        // mutators
        auto special_collection_class(const special_collection_class_type& _c) -> void { sc_->collClass = _c; }

        auto struct_file(const struct_file_type& _t) -> void { sc_->type = _t; }

        auto collection(std::string_view _c) -> void { set_string_property(sc_->collection, _c, sizeof(sc_->collection)); }

        auto logical_path(std::string_view _p) -> void { set_string_property(sc_->objPath, _p, sizeof(sc_->objPath)); }

        auto resource_name(std::string_view _r) -> void { set_string_property(sc_->resource, _r, sizeof(sc_->resource)); }

        auto resource_hierarchy(std::string_view _h) -> void { set_string_property(sc_->rescHier, _h, sizeof(sc_->rescHier)); }

        auto physical_path(std::string_view _p) -> void { set_string_property(sc_->phyPath, _p, sizeof(sc_->phyPath)); }

        auto cache_directory(std::string_view _d) -> void { set_string_property(sc_->cacheDir, _d, sizeof(sc_->cacheDir)); }

        auto cache_is_dirty(const int _d) -> void { sc_->cacheDirty = _d; }

        auto replica_number(const int _n) -> void { sc_->replNum = _n; }

        auto get() noexcept -> sc_pointer_type { return sc_; }

    private:
        sc_pointer_type sc_;

        static auto set_string_property(
            char* _dst,
            std::string_view _src,
            const std::size_t _dst_size) -> void
        {
            if (_src.size() >= _dst_size) {
                THROW(USER_STRLEN_TOOLONG, "source length exceeds destination buffer length");
            }
            std::memset(_dst, 0, _dst_size);
            std::strncpy(_dst, _src.data(), _dst_size);
        }

    }; // class special_collection_proxy

    template<typename sc_type>
    static auto make_special_collection_proxy(sc_type& _sc) -> special_collection_proxy<sc_type>
    {
        return special_collection_proxy{_sc};
    }

} // namespace irods::experimental

#endif // IRODS_SPECIAL_COLLECTION_PROXY_HPP

