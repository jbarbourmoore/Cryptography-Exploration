#ifndef GCMBlock_HPP
#define GCMBlock_HPP

#include "AES.hpp"
#include "inttypes.h"

class GCMBlock{

    private :
        unsigned __int128 block;

    public:
        GCMBlock();

        GCMBlock(AESDataBlock input);

        GCMBlock(GCMBlock const &input);

        GCMBlock(std::string input);

        void galoisMultiplication(GCMBlock const &other);

        void operator>>(int shift_bits);

        void operator<<(int shift_bits);

        bool operator==(GCMBlock const &other) const;

        void increment(int increment_value);

        void print() const;

        std::string getHexString() const;
};


#endif